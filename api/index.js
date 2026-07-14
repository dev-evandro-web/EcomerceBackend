// ======================================================
// IMPORTANDO FRAMEWORK EXPRESS E MÓDULOS NATIVOS
// ======================================================
require("dotenv").config();
const express = require("express");
const app = express();
const path = require("path");

// ======================================================
// IMPORTAR MÓDULOS DE TERCEIROS
// =======================================================
const Sequelize = require("sequelize");
const handlebars = require("express-handlebars");

// ========================================================
// IMPORTAÇÃO PARA AUTENTICAÇÃO E SESSÃO
//=========================================================
const session = require("express-session"); // OBRIGATÓRIO instalar: npm i express-session
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");

// ========================================================
// CONFIGURAÇÃO DE HANDLEBARS E ARQUIVOS ESTÁTICOS
// =========================================================
const { engine } = require('express-handlebars');
const path = require('path');

app.engine('handlebars', engine({
  defaultLayout: 'main',
  layoutsDir: path.join(__dirname, '../views/layouts')
}));
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, '../views/layouts'));


// ====================================================================
// CONFIGURAÇÃO DE BODY PARSER
// =====================================================================
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// =======================================================
// CONFIGURAÇÃO DE SESSÃO (ESSENCIAL PARA O PASSPORT NO VERCEL)
// =======================================================
app.use(session({
    secret: process.env.SESSION_SECRET || "chave-secreta-ecommerce",
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === "production", // True apenas se usar HTTPS (Vercel usa por padrão)
        maxAge: 24 * 60 * 60 * 1000, // Mantém logado por 1 dia
        sameSite: 'lax'
    }
}));

// INICIALIZAÇÃO DO PASSPORT
app.use(passport.initialize());
app.use(passport.session()); 

// ==============================================================
// MIDDLEWARE PERSONALIZADO (PASSAR USUÁRIO PARA AS VIEWS)
// ==============================================================
app.use(function(req, res, next) {
    res.locals.user = req.user || null;
    next();
});

// ============================================================
// CONEXÃO COM O BANCO DE DADOS (MySQL - Otimizado para Serverless)
// ===========================================================
const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
    console.error("ERRO CRÍTICO: DATABASE_URL não foi definida nas Variáveis de Ambiente!");
}

const sequelize = new Sequelize(databaseUrl, {
  dialect: 'mysql',
  logging: false,
  dialectModule: require('mysql2'), // OBRIGATÓRIO para funcionar no Vercel
  pool: {
    max: 5,      // Limita conexões para não estourar o Clever Cloud
    min: 0,
    acquire: 30000,
    idle: 10000
  },
  dialectOptions: {}
});

sequelize.authenticate()
    .then(() => console.log("Conectado ao banco de dados com sucesso!"))
    .catch(erro => console.error("Erro ao conectar no banco MySQL: " + erro));

// ==============================================================
// MODEL DE USUÁRIOS
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

// Sincroniza sem travar o carregamento do Serverless
sequelize.sync()
    .then(() => console.log("Tabelas sincronizadas"))
    .catch(err => console.error("Erro na sincronização de tabelas: ", err));

// ============================================================
// CONFIGURAÇÃO DO PASSPORT - ESTRATÉGIA LOCAL
// ==============================================================
passport.use(new LocalStrategy(
{
    usernameField: 'email',
    passwordField: 'senha'
},
(email, senha, done)=>{
    Ecomerce.findOne({ where:{ email: email } }).then(usuario=>{
        if(!usuario){
            return done(null, false, { message: "Usuário não encontrado" });
        }
        bcrypt.compare(senha, usuario.senha, (erro, resultado)=>{
            if(resultado){
                return done(null, usuario);
            } else {
                return done(null, false, { message: "Senha incorreta" });
            }
        });
    }).catch((erro)=>{
        return done(erro);
    });
}));
        
passport.serializeUser((usuario, done) => {
    done(null, usuario.id);
});

passport.deserializeUser((id, done) => {
    Ecomerce.findByPk(id).then((usuario) => {
        // Converte para objeto plano para o Handlebars conseguir ler sem erros de segurança
        done(null, usuario ? usuario.get({ plain: true }) : null);
    }).catch((err) => {
        done(err, null);
    });
});

// ==============================================
// MIDDLEWARE DE AUTENTICAÇÃO
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
app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login"
}));

app.get("/Registro", (req, res) => {
    res.render("layouts/Registro");
});

app.post("/Registro/novo", (req, res) => {
    if (req.body.senha !== req.body.confirma_senha) {
        return res.redirect("/Registro?erro=senhas");
    }
    Ecomerce.findOne({ where: { email: req.body.email } }).then((usuario) => {
        if (usuario) {
            return res.redirect("/Registro?erro=email");
        } else {
            bcrypt.genSalt(10, (erro, salt) => {
                bcrypt.hash(req.body.senha, salt, (erro, hash) => {
                    if (erro) {
                        return res.redirect("/Registro?erro=hash");
                    }
                    Ecomerce.create({
                        nome: req.body.nome,
                        email: req.body.email,
                        senha: hash,
                        confirma_senha: hash
                    }).then(() => {
                        res.redirect("/login?sucesso=Registro");
                    }).catch((err) => {
                        console.error("Erro ao criar Registro: ", err);
                        return res.redirect("/Registro?erro=criar");
                    });
                });
            });
        }
    }).catch(err => {
        console.error("Erro ao verificar email no Registro: ", err);
        res.status(500).send("Erro interno ao processar Registro");
    });
}); 

app.get("/logout", (req, res, next) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect("/login?sucesso=logout");
    });
});

app.get("/", (req, res) => {
    res.redirect("/login"); 
});

// =============================================
// ROTAS DO CRUD 
// =============================================
app.get("/ler", verificarAuthenticacao, function(req, res) {
    Ecomerce.findAll({ order: [['id', 'DESC']] })
    .then(function(usuarios) {
        // Mapeia para objetos puros para evitar erros do Handlebars em produção
        const usuariosPuros = usuarios.map(u => u.get({ plain: true }));
        res.render("listagem", { usuarios: usuariosPuros, user_logado: req.user });
    })
    .catch(function(erro) {
        console.error("Erro ao buscar usuários: ", erro);
        res.redirect("/login?erro=buscar");
    });
});

app.get("/cadastro", verificarAuthenticacao, function(req, res) {
    res.render("cadastro", { usuario: req.user });
});

app.post("/receber", verificarAuthenticacao, function(req, res) {
    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(req.body.senha, salt, (err, hash) => { 
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
    Ecomerce.destroy({ where: { id: req.params.id } })
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
            usuario_editar: usuario ? usuario.get({ plain: true }) : null, 
            usuario: req.user 
        });
    })
    .catch(function(erro) {
        res.redirect("/ler?erro=nao_encontrado");
    });
});

app.post("/atualizar", verificarAuthenticacao, function(req, res) {
    Ecomerce.update(
        { nome: req.body.nome, email: req.body.email },
        { where: { id: req.body.id } }
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
// OUTRAS PÁGINAS
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
// ROTA DASHBOARD
// =========================
app.get("/dashboard", verificarAuthenticacao, function(req, res){
    res.render("dashboard", { usuario: req.user });
});

// =============================================================
// INICIALIZA O SERVIDOR - SÓ LOCAL
// =============================================================
const porta = process.env.PORT || 3000;

if (process.env.NODE_ENV !== "production") {
  app.listen(porta, () => {
    console.log('Servidor rodando na porta ${porta}');
  });
}

module.exports = app;
module.exports.default = app;