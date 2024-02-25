 require('dotenv').config()
 const express = require('express')
 const mongoose = require('mongoose')
 const bcrypt = require('bcrypt')
 const jwt = require('jsonwebtoken')

 const app = express()

// Models

const User = require('./models/User')


 // CONFIG JSON

 app.use(express.json())

// Public Route
app.get('/', (req, res) => {
    res.status(200).json({msg: "Bem vindo a nossa API"})
})

//Private Route
app.get('/user/:id', checkToken, async (req, res) => {

    const id = req.params.id

    // check if user exists
    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(404).json({msg: "Usuario nao encontrado"})
    }

    res.status(200).json({ user })

})
function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token) {
        return res.status(401).json({msg: "Acesso negado"})
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch (error) {
        res.status(400).json({msg: "Token invalido"})
    }
}



// Register User
app.post('/auth/register', async(req, res) => {

    const { name, email, password, confirmpassword } = req.body

    // validações
    if(!name) {
        return res.status(422).json({ msg: "O nome é obrigatorio" })
    }
    if(!email) {
        return res.status(422).json({ msg: "O email é obrigatorio" })
    }
    if(!password) {
        return res.status(422).json({ msg: "A senha é obrigatoria" })
    }

    if(password !== confirmpassword) {

        return res.status(422).json({msg: "As senhas não conferem"})
    }

        // check if user exists

        const userExists = await User.findOne({ email: email })

        if(userExists) {
            return res.status(422).json({msg: "Por favor utilize outro email"})
        }

    // create password

    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try{
        await user.save()
        
        res.status(201).json({ msg: "Usuario criado com sucesso"})


    }catch(error){
        res.status(500).json({msg: "aconteceu um erro"})
    }
})

// Login User
app.post('/auth/login', async (req, res) => {

    const { email, password } = req.body

    if(!email) {
        return res.status(422).json({ msg: "O email é obrigatorio" })
    }
    if(!password) {
        return res.status(422).json({ msg: "A senha é obrigatoria" })
    }

// check if exists

    const user = await User.findOne({ email: email })
    
    if(!user){
        return res.status(404).json({msg: "Usuario nao encontrado"})
    }


// check if password exists
    const checkPassword = await bcrypt.compare(password, user.password)
    
    if(!checkPassword) {
        return res.status(422).json({msg: "Senha invalida"})
    }

    try {
        
        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret
        )

        res.status(200).json({ msg: "Autenticação realizada com sucesso", token})

    } catch (error) {
        console.log(error)
        res.status(500).json({
            msg: "Aconteceu um erro no servidor, tente mais tarde"
        })
    }



})


//CREDENCIAIS

const dbUser = process.env.DB_USER
const dbPass = process.env.DB_pass

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@authjwt.awqyy6y.mongodb.net/?retryWrites=true&w=majority&appName=authjwt`).then(() => {
    app.listen(3000)
    console.log('Conectou ao banco')
}).catch((err) => console.log(err))


