require("dotenv").config()
const jwt = require("jsonwebtoken")
const sanitizeHTML = require("sanitize-html")
const bcrypt = require("bcrypt")
const cookieParser = require("cookie-parser")
const express = require("express")
const db = require("better-sqlite3")("ourApp.db")
db.pragma("journal_mode = WAL")
// database setup starts here
const createTables = db.transaction(() => {
    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
        `
    ).run()

    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS posts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body TEXT NOT NULL,
        authorid INTEGER,
        FOREIGN KEY (authorid) REFERENCES users (id)
        )
        `
    ).run()
})
createTables()

// database setup ends here 
const app = express()
app.set ("view engine", "ejs")
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"))
app.use(cookieParser())

app.use (function(req, res, next){
    // try to decode incoming cookie
    try{
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
        req.user = decoded
    }catch(err){
        req.user = false
    }

    res.locals.user = req.user
    res.locals.errors =[]
    
    next()
})

app.get("/", (req, res)=> {
    if (req.user){
        const statement = db.prepare("SELECT * FROM posts WHERE authorid = ? ORDER BY createdDate DESC")
        const posts = statement.all(req.user.userID)
        
        return res.render("dashboard", {posts})
    }
    res.render("homepage")  
})

app.get("/createpost", mustBeLoggedIn, (req, res)=> {
    res.render("createpost")
})

app.get("/login", (req, res)=> {
    res.render("login")
})

app.get("/editpost/:id", (req, res)=>{
    //try to lookup the post in question
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

    // if user is not post author redirect to homepage
    if (post.authorid !== req.user.userID) {
        return res.redirect("/")
    }

    // if post does not exist
    if (!post) {
        return res.redirect("/")
    }

    // otherwise allow edit and view edit template
    return res.render("editpost", { post })
})

app.post("/deletepost/:id", (req,res)=>{
    //try to lookup the post in question
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)
    
    // if user is not post author redirect to homepage
    if (post.authorid !== req.user.userID) {
        return res.redirect("/")
    }

    // if post does not exist
    if (!post) {
        return res.redirect("/")
    }
    
    const deleteStatement = db.prepare("DELETE FROM posts WHERE id=?")
    deleteStatement.run(req.params.id)
    
    res.redirect("/")
})

app.post("/editpost/:id", (req,res)=>{
    //try to lookup the post in question
    const statement = db.prepare("SELECT * FROM posts WHERE id = ?")
    const post = statement.get(req.params.id)

    // if user is not post author redirect to homepage
    if (post.authorid !== req.user.userID) {
        return res.redirect("/")
    }

    // if post does not exist
    if (!post) {
        return res.redirect("/")
    }

    // check for validation and sanitize updates
    const errors = sharedPostValidation(req)

    if(errors.length) {
        return res.render("editpost", {errors})
    }

    // if no errors update DB
    const updadeStatement = db.prepare("UPDATE posts SET title = ?, body = ? WHERE id = ?")
    updadeStatement.run(req.body.title, req.body.body, req.params.id)

    res.redirect(`/post/${req.params.id}`)    
})

app.get("/post/:id", (req, res)=>{
    const statement = db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?")
    const post = statement.get(req.params.id)

    if (!post) {
        return res.redirect("/")
    }

    const isAuthor = post.authorid === req.user.userID
    return res.render("singlepost", { post, isAuthor })
})

app.get("/logout", (req, res)=> {
    res.clearCookie("ourSimpleApp")
    res.redirect("/")
})

function mustBeLoggedIn(req, res, next){
    if(req.user){
        return next()
    }
    return res.redirect("/")
}

function sharedPostValidation (req){
    const errors = []

    if (typeof req.body.title !== "string") {req.body.title =""}
    if (typeof req.body.body !== "string") {req.body.body =""}

    // trim or sanitize or strip out html
    req.body.title = sanitizeHTML(req.body.title.trim(), {allowedTags:[], allowedAttributes:{}})
    req.body.body = sanitizeHTML(req.body.body.trim(), {allowedTags:[], allowedAttributes:{}})

    if (!req.body.title) errors.push("You must provide a title")
    if (!req.body.body) errors.push("You must provide content")
            
    return errors
}

app.post("/createpost", mustBeLoggedIn, (req, res)=> {

    const errors = sharedPostValidation(req)

    if (errors.length) return res.render ("createpost", {errors})

    // if no errors, save into database
    const ourStatement = db.prepare("INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)")
    const result = ourStatement.run(req.body.title, req.body.body, req.user.userID, new Date().toISOString() )

    // redirect user to view his newly added post
    const getPostStatement = db.prepare('SELECT * FROM posts WHERE Rowid = ?')
    const realPost = getPostStatement.get(result.lastInsertRowid)

    res.redirect(`/post/${realPost.id}`)
})

app.post("/login", (req, res)=> {
    let errors = []

    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    req.body.username = req.body.username.trim()
    if(!req.body.username) errors= ["INVALID USERNAME OR PASSWORD"]
    if(!req.body.password) errors= ["INVALID USERNAME OR PASSWORD"]
    
    if (errors.length) {
        return res.render("login",{errors} )
    }

    // First Look for matching username in DB

    const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const userInQuestion = userInQuestionStatement.get(req.body.username)

    if(!userInQuestion) {
        errors= ["INVALID USERNAME OR PASSWORD"]
        return res.render("login",{errors} )
    }

    // We have valid username that exists in DB now we compare PASSWORD 
    
    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    
    if(!matchOrNot){
        errors= ["INVALID USERNAME OR PASSWORD"]
        return res.render("login",{errors} )
    }

    // if Username and password match DB LOG USER IN AND COOKIE
    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now()/1000) + 60 * 60 * 24, username: userInQuestion.username, userID: userInQuestion.id},process.env.JWTSECRET)

    res.cookie("ourSimpleApp",ourTokenValue,{
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    res.redirect("/")
})

app.post("/register", (req, res)=> {
    const errors = []

    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    req.body.username = req.body.username.trim()

    if(!req.body.username) errors.push("USER MUST PROVIDE A USERNAME")
    if(req.body.username && req.body.username.length < 3) errors.push("USERNAME CANNOT BE SHORTER THAN 3 CHARACTERS")
    if(req.body.username && req.body.username.length > 10) errors.push("USERNAME CANNOT BE LONGER THAN 10 CHARACTERS")
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("ONLY LETTERS AND NUMBERS ALLOWED")
    // check if Username already taken
    const usernameStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const usernameCheck = usernameStatement.get(req.body.username)

    if(usernameCheck) errors.push ("THIS USERNAME IS ALREADY TAKEN")

    if(!req.body.password) errors.push("USER MUST PROVIDE A PASSWORD")
    if(req.body.password && req.body.password.length < 8) errors.push("PASSWORD MUST BE AT LEAST 8 CHARACTERS")
    if(req.body.password && req.body.password.length > 15) errors.push("PASSWORD CANNOT BE LONGER THAN 15 CHARACTERS")

    if (errors.length) {
        return res.render("homepage",{errors} )
    }

    // SAVE USER TO DATABASE
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES(?, ?)")
    const result = ourStatement.run(req.body.username, req.body.password)

    const lookUpStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ourUser = lookUpStatement.get(result.lastInsertRowid)
    
    // LOG USER IN AND COOKIE
    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now()/1000) + 60 * 60 * 24, username: ourUser.username, userID: ourUser.id},process.env.JWTSECRET)

    res.cookie("ourSimpleApp",ourTokenValue,{
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    res.redirect("/")
})

app.listen(3000)