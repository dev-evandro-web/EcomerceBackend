// ======================================================
// IMPORTANDO FRAMEWORK EXPRESS E MÓDULOS NATIVOS
// IMPORTANDO FRAMEWORK EXPRESS E MÓDULOS NATIVOS
import express from 'express';
import exphbs from 'express-handlebars';
import path from 'path';
const app = express();

// IMPORTAR MÓDULOS DE TERCEIROS
import { Sequelize } from 'sequelize';
import mysql2 from 'mysql2';

// IMPORTAÇÃO PARA AUTENTICAÇÃO E SESSÃO
import session from 'express-session';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import dotenv from 'dotenv';
dotenv.config();

import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ========================================================
// CONFIGURAÇÃO DE HANDLEBARS E ARQUIVOS ESTÁTICOS
// =========================================================
app.engine('handlebars', exphbs.engine({
    defaultLayout: 'main',
    layoutsDir: path.join(__dirname, 'views/layouts'),
    partialsDir: path.join(__dirname, 'views/partials')
}));
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

// Servir CSS, JS, Imagens
app.use(express.static(path.join(__dirname, 'public')));

// ====================================================================
// CONFIGURAÇÃO DE BODY PARSER
// =====================================================================
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// =======================================================
// CONFIGURAÇÃO DE SESSÃO
// =======================================================
app.use(session({
    secret: process.env.SESSION_SECRET || "chave-secreta-ecommerce",
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === "production", 
        maxAge: 24 * 60 * 60 * 1000, 
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
// CONEXÃO COM O BANCO DE DADOS (MySQL)
// ===========================================================



// CONEXÃO COM O BANCO DE DADOS (MySQL)
const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASS,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'mysql',
    dialectModule: mysql2,
    dialectOptions: { ssl: { rejectUnauthorized: false } },
    logging: false
  }
);

sequelize.authenticate()
  .then(() => console.log('Banco conectado com sucesso'))
  .catch(err => console.error('Erro ao conectar:', err));
  



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

// Sincroniza
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
    res.render("Registro");
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
// ===========================================
// =============================================================
// INICIALIZA O SERVIDOR - PRA LOCAL E PRA RAILWAY
// =============================================================
const porta = Number(process.env.PORT) || 3000;

app.listen(porta, () => {
    console.log(`Servidor rodando na porta ${porta}`);
});

// ===========================================
// EXPORT PRA RAILWAY
// ===========================================
module.exports = app;