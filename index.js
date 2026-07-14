//=====================================================
// IMPORTANDO FRAMEWORK EXPRESS
//======================================================
require("dotenv").config();
const express = require("express");
const app = express();

// ======================================================
//        IMPORTAR MÓDULOS
// =======================================================
const Sequelize = require("sequelize");
const handlebars = require("express-handlebars");

// ========================================================
// IMPORTAÇÃO PARA AUTENTICAÇÃO 
//=========================================================
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
const session = require("express-session"); // REABILITADO
const flash = require("connect-flash");     // REABILITADO

// ========================================================
// CONFIGURAÇÃO DE HANDLEBARS
// =========================================================
app.engine("handlebars", handlebars.engine({
    allowProtoPropertiesByDefault: true,
    allowProtoMethodsByDefault: true,
    helpers: {
        isAuthenticated: function(req) {
            return req.isAuthenticated();
        }
    },
    currentUser: function(req) {
        return req.user;
    }
}));

app.set("view engine", "handlebars");
app.set("views", "./views");
app.use(express.static("public"));

// ====================================================================
// CONFIGURAÇÃO DE BODY PARSER
// =====================================================================
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// =====================================================================
// CONFIGURAÇÃO DE SESSÕES (Necessário para Passport e Flash funcionarem)
// =====================================================================
app.use(session({
    secret: process.env.SESSION_SECRET || "chave_secreta_provisoria", // Evita crash se o .env sumir
    resave: false, 
    saveUninitialized: false, 
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 // 24 horas
    }
}));

// ==========================================================
// CONFIGURAÇÃO DO FLASH
// =========================================================
app.use(flash()); // REABILITADO

// =======================================================
// INICIALIZAÇÃO DO PASSPORT
// =======================================================
app.use(passport.initialize());
app.use(passport.session()); // REABILITADO para persistir a sessão de login

// ==============================================================
// MIDDLEWARE PERSONALIZADO
// ==============================================================
app.use(function(req, res, next) {
    res.locals.success_msg = req.flash("success_msg"); 
    res.locals.error_msg = req.flash("error_msg");
    res.locals.error = req.flash("error");
    res.locals.user = req.user || null;
    next();
});

// ============================================================
// CONEXÃO COM O BANCO DE DADOS
// ===========================================================
// Certifique-se de preencher a variável DATABASE_URL no painel da Vercel!
const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
    console.error("ERRO CRÍTICO: A variável DATABASE_URL não está definida no ambiente.");
}

const sequelize = new Sequelize(databaseUrl, {
  dialect: 'mysql',
  logging: false,
  dialectModule: require('mysql2'), // Recomendado para Vercel
  dialectOptions: {
    ssl: {
      rejectUnauthorized: false // <--- ISSO AQUI resolve o problema de conexão segura com a Railway!
    }
  }
});


// ==============================================================
// CRIANDO TABELA USUÁRIOS
// ==============================================================
const Ecomerce = sequelize.define("ecomerce", {
    nome: {
        type: Sequelize.STRING,
        allowNull: false
    },
    email: {
        type: Sequelize.STRING,
        allowNull: false
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

// ============================================================
// CONFIGURAÇÃO DO PASSPORT - ESTRATÉGIA LOCAL
// ==============================================================
passport.use(new LocalStrategy(
{
    usernameField: 'email',
    passwordField: 'senha'
},
(email, senha, done)=>{
    Ecomerce.findOne({
        where:{ email: email }
    }).then(usuario=>{
        if(!usuario){
            return done(null,false,{
                message:"Usuário não encontrado"
            });
        }

        bcrypt.compare(senha, usuario.senha,(erro,resultado)=>{
            if(resultado){
                return done(null,usuario);
            }else{
                return done(null,false,{
                    message:"Senha incorreta"
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
// MIDDLEWARE DE AUTENTICAÇÃO
// ==============================================
function verificarAuthenticacao(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    req.flash("error_msg", "Você precisa estar logado para acessar esta página.");
    res.redirect("/login");
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
    failureRedirect: "/login",
    failureFlash: true
}));

// Tela de Registro de Usuários (Público)
app.get("/registro", (req, res) => {
    res.render("registro");
});

// Processar Registro com Criptografia
app.post("/registro/novo", (req, res) => {
    if (req.body.senha !== req.body.confirma_senha) {
        req.flash("error_msg", "As senhas não coincidem.");
        return res.redirect("/registro");
    }

    Ecomerce.findOne({ where: { email: req.body.email } }).then((usuario) => {
        if (usuario) {
            req.flash("error_msg", "Este e-mail já está cadastrado.");
            res.redirect("/registro");
        } else {
            bcrypt.genSalt(10, (erro, salt) => {
                bcrypt.hash(req.body.senha, salt, (erro, hash) => {
                    if (erro) {
                        req.flash("error_msg", "Erro no salvamento do usuário.");
                        res.redirect("/registro");
                    }

                    Ecomerce.create({
                        nome: req.body.nome,
                        email: req.body.email,
                        senha: hash,
                        confirma_senha: hash
                    }).then(() => {
                        req.flash("success_msg", "Usuário registrado com sucesso! Faça login.");
                        res.redirect("/login");
                    }).catch((err) => {
                        req.flash("error_msg", "Erro ao criar usuário.");
                       return res.redirect("/registro");
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
        req.flash("success_msg", "Deslogado com sucesso.");
        res.redirect("/login");
    });
});


// Adicione isso junto com as suas outras rotas
app.get("/", (req, res) => {
    res.redirect("/login"); 
});

// =============================================
// ROTAS DO CRUD ORIGINAL (PROTEGIDOS)
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
        req.flash("error_msg", "Erro ao buscar usuários");
        res.redirect("/home");
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
                req.flash("success_msg", "Usuário cadastrado com sucesso");
                res.redirect("/login");
            })
            .catch(function(erro) {
                req.flash("error_msg", "Erro ao cadastrar usuário");
                res.redirect("/cadastro");
            });
        });
    });
});

app.get("/deletar/:id", verificarAuthenticacao, function(req, res) {
    Ecomerce.destroy({
        where: { id: req.params.id }
    })
    .then(function() {
        req.flash("success_msg", "Usuário deletado com sucesso!");
        res.redirect("/ler");
    })
    .catch(function(erro) {
        req.flash("error_msg", "Erro ao deletar usuário.");
        res.redirect("/ler");
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
        req.flash("error_msg", "Usuário não encontrado");
        res.redirect("/ler");
    });
});

app.post("/atualizar", verificarAuthenticacao, function(req, res) {
    Ecomerce.update(
        {
            nome: req.body.nome,
            sobrenome: req.body.sobrenome,
            idade: req.body.idade,
            email: req.body.email
        },
        {
            where: { id: req.body.id } 
        }
    )
    .then(function() {
        req.flash("success_msg", "Usuário atualizado com sucesso!");
        res.redirect("/ler");
    })
    .catch(function(erro) {
        req.flash("error_msg", "Erro ao atualizar usuário");
        res.redirect("/ler");
    });
});

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
// TRABALHANDO COM PRODUTOS 
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
    res.render("dashboard", {
        usuario: req.user
    });
});

// =============================================================
// INICIALIZA O SERVIDOR
// =============================================================
const porta = process.env.PORT || 3000;

// Garante que o servidor rode localmente, mas permite que a Vercel controle a exportação
if (process.env.NODE_ENV !== 'production') {
    app.listen(porta, () => {
        console.log("Servidor rodando localmente na porta ${porta}");
    });
}

module.exports = app;