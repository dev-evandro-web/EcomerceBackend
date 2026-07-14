// ======================================================
// IMPORTANDO FRAMEWORK EXPRESS E MÓDULOS NATIVOS
// ======================================================
require("dotenv").config();
const express = require("express");
const app = express();
const path = require("path"); // MÓDULO NATIVO DO NODE.JS

// ======================================================
// IMPORTAR MÓDULOS DE TERCEIROS
// =======================================================
const Sequelize = require("sequelize");
const handlebars = require("express-handlebars");

// ========================================================
// IMPORTAÇÃO PARA AUTENTICAÇÃO
//=========================================================
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");

// ========================================================
// CONFIGURAÇÃO DE HANDLEBARS E ARQUIVOS ESTÁTICOS
// =========================================================
app.engine("handlebars", handlebars.engine({
    allowProtoPropertiesByDefault: true,
    allowProtoMethodsByDefault: true
}));

app.set("view engine", "handlebars");
app.set("views", path.join(__dirname, "views")); 
app.use(express.static(path.join(__dirname, "public"))); 

// ====================================================================
// CONFIGURAÇÃO DE BODY PARSER
// =====================================================================
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// =======================================================
// INICIALIZAÇÃO DO PASSPORT - SEM SESSION
// =======================================================
app.use(passport.initialize());

// ==============================================================
// MIDDLEWARE PERSONALIZADO
// ==============================================================
app.use(function(req, res, next) {
    res.locals.user = req.user || null;
    next();
});

// ============================================================
// CONEXÃO COM O BANCO DE DADOS
// ===========================================================
const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
    console.error("ERRO CRÍTICO: A variável DATABASE_URL não está definida no ambiente.");
} else {
    console.log("Variável DATABASE_URL encontrada, tentando conectar...");
}

const sequelize = new Sequelize(databaseUrl, {
  dialect: 'mysql',
  logging: false,
  dialectModule: require('mysql2'), 
  dialectOptions: {
    ssl: {
      require: true,
      rejectUnauthorized: false // Obrigatório pro Clever Cloud
    }
  }
});

sequelize.authenticate()
    .then(() => console.log("Conectado ao banco de dados com sucesso"))
    .catch(erro => console.log("Erro ao se conectar com o banco de dados: " + erro));

// ==============================================================
// CRIANDO TABELA USUÁRIOS
// ==============================================================
const Ecomerce = sequelize.define("ecomerce", {
    id: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    nome: {
        type: Sequelize.STRING,
        allowNull: false
    },
    email: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true
    },
    senha: {
        type: Sequelize.STRING,
        allowNull: false
    },
    confirma_senha: {
        type: Sequelize.STRING,
        allowNull: false
    }
}, {
    tableName: "ecomerce",
    timestamps: false
});

// Sincroniza a tabela 1x. Depois pode comentar
sequelize.sync();

// ============================================================
// CONFIGURAÇÃO DO PASSPORT - ESTRATÉGIA LOCAL
// ==============================================================
passport.use(new LocalStrategy(
{
    usernameField: 'email',
    passwordField: 'senha',
    passReqToCallback: false
},
(email, senha, done)=>{
    Ecomerce.findOne({
        where:{ email: email }
    }).then(usuario=>{
        if(!usuario){
            return done(null, false, {
                message: "Usuário não encontrado"
            });
        }

        bcrypt.compare(senha, usuario.senha, (erro, resultado)=>{
            if(resultado){
                return done(null, usuario);
            } else {
                return done(null, false, {
                    message: "Senha incorreta"
                });
            }
        });
    }).catch((erro)=>{
        return done(erro);
    });
}));
        
// =============================================
// SERIALIZE E DESERIALIZE USER
// ==============================================
passport.serializeUser((usuario, done) => {
    done(null, usuario.id);
});

passport.deserializeUser((id, done) => {
    Ecomerce.findByPk(id).then((usuario) => {
        done(null, usuario);
    }).catch((err) => {
        done(err, null);
    });
});

// ==============================================
// MIDDLEWARE DE AUTENTICAÇÃO SEM FLASH
// ==============================================
function verificarAuthenticacao(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login?erro=nao_logado");
}

// ==============================================
// ROTAS DE AUTENTICAÇÃO
// ==============================================

// Tela de Login
app.get("/login", (req, res) => {
    res.render("login");
});

// Processar o Login
app.post("/login", passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login"
}));

// Tela de Registro de Usuários (Público)
app.get("/registro", (req, res) => {
    res.render("registro");
});

// Processar Registro com Criptografia
app.post("/registro/novo", (req, res) => {
    if (req.body.senha !== req.body.confirma_senha) {
        return res.redirect("/registro?erro=senhas");
    }

    Ecomerce.findOne({ where: { email: req.body.email } }).then((usuario) => {
        if (usuario) {
            return res.redirect("/registro?erro=email");
        } else {
            bcrypt.genSalt(10, (erro, salt) => {
                bcrypt.hash(req.body.senha, salt, (erro, hash) => {
                    if (erro) {
                        return res.redirect("/registro?erro=hash");
                    }

                    Ecomerce.create({
                        nome: req.body.nome,
                        email: req.body.email,
                        senha: hash,
                        confirma_senha: hash
                    }).then(() => {
                        res.redirect("/login?sucesso=registro");
                    }).catch((err) => {
                        return res.redirect("/registro?erro=criar");
                    });
                });
            });
        }
    });
}); 

// Rota de Logout
app.get("/logout", (req, res, next) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect("/login?sucesso=logout");
    });
});

// Rota raiz redireciona para login
app.get("/", (req, res) => {
    res.redirect("/login"); 
});

// =============================================
// ROTAS DO CRUD (PROTEGIDOS)
// =============================================

app.get("/ler", verificarAuthenticacao, function(req, res) {
    Ecomerce.findAll({ order: [['id', 'DESC']] })
    .then(function(usuarios) {
        res.render("listagem", {
            usuarios: usuarios,
            user_logado: req.user 
        });
    })
    .catch(function(erro) {
        res.redirect("/login?erro=buscar");
    });
});

app.get("/cadastro", verificarAuthenticacao, function(req, res) {
    res.render("cadastro", { usuario: req.user });
});

app.post("/receber", verificarAuthenticacao, function(req, res) {
    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash("null", salt, (err, hash) => { 
            Ecomerce.create({
                nome: req.body.nome,
                email: req.body.email,
                senha: hash,
                confirma_senha: hash
            })
            .then(function() {
                res.redirect("/ler?sucesso=cadastro");
            })
            .catch(function(erro) {
                res.redirect("/cadastro?erro=cadastro");
            });
        });
    });
});

app.get("/deletar/:id", verificarAuthenticacao, function(req, res) {
    Ecomerce.destroy({
        where: { id: req.params.id }
    })
    .then(function() {
        res.redirect("/ler?sucesso=deletar");
    })
    .catch(function(erro) {
        res.redirect("/ler?erro=deletar");
    });
});

app.get("/editar/:id", verificarAuthenticacao, function(req, res) {
    Ecomerce.findByPk(req.params.id)
    .then(function(usuario) {
        res.render("editar", {
            usuario_editar: usuario,
            usuario: req.user
        });
    })
    .catch(function(erro) {
        res.redirect("/ler?erro=nao_encontrado");
    });
});

app.post("/atualizar", verificarAuthenticacao, function(req, res) {
    Ecomerce.update(
        {
            nome: req.body.nome,
            email: req.body.email
        },
        {
            where: { id: req.body.id } 
        }
    )
    .then(function() {
        res.redirect("/ler?sucesso=atualizar");
    })
    .catch(function(erro) {
        res.redirect("/ler?erro=atualizar");
    });
});

// API de usuários
app.get("/api/usuarios", function(req, res) {
    Ecomerce.findAll({ order: [['id', 'DESC']] })
    .then(function(usuarios) {
        res.json(usuarios); 
    })
    .catch(function(erro) {
        res.status(500).json({ erro: "Erro ao buscar dados" });
    });
});

// ==============================================================
// TRABALHANDO COM PRODUTOS (ROTAS PÚBLICAS)
// =============================================================
app.get("/produtos", (req, res) => {
    res.render("produtos");
});

app.get("/home", (req, res) => {
    res.render("home");
});

app.get("/produto/:id", (req, res) => {
    const id = req.params.id;
    res.send("Produto ID: " + id);
});

// ==========================
// ROTA DASHBOARD (PROTEGIDO)
// =========================
app.get("/dashboard", verificarAuthenticacao, function(req, res){
    res.render("dashboard", {
        usuario: req.user
    });
});

// =============================================================
// INICIALIZA O SERVIDOR - SÓ LOCAL
// =============================================================
const porta = process.env.PORT || 3000;

if (process.env.NODE_ENV !== "production") {
  app.listen(porta, () => {
    console.log("Servidor rodando na porta ${porta}");
  });
}

module.exports = app;