// Requisições

require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const User = require('./models/User')

app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo a minha API' })
})

// Rota privada

app.get('/user/:id', checkToken, async (req, res) => {
    
    const id = req.params.id

    // Checar User
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(404).json({msg: 'usuário nao encontrado'})
    }
    res.status(200).json({ user })
})

function checkToken(req, res, next){

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({ msg: 'Acesso negado!'})
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()
    } catch(error){
        res.status(400).json({msg: 'token invalido'})
    }

}

app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmpassword} = req.body

    if(!name) {
        return res.status(422).json({msg: "O nome é obrigatorio."})
    }

    if(!email) {
        return res.status(422).json({msg: "O email é obrigatorio."})
    }

    if(!password) {
        return res.status(422).json({msg: "A senha é obrigatorio."})
    }

    if(password !== confirmpassword) {
        return res.status(422).json({msg: "A senha não confere."})
    }


// Checar se o user existe

    const userExist = await User.findOne({ email:email })

    if (userExist){
        return res.status(422).json({msg: "Esse email já existe."})
    }

// Criando senha

    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

// Criando usuario

    const user = new User({
        name,
        email,
       password: passwordHash,
    })

    try {

        await user.save()

        res.status(201).json({msg: 'Usuario criado com sucesso!'})

    } catch(error) {

        res.status(500).json({ msg: error })

    }

})


    app.post("/auth/user", async (req, res) => {

        const { email, password } = req.body


        if(!email) {
            return res.status(422).json({msg: "O email é obrigatorio."})
        }
    
        if(!password) {
            return res.status(422).json({msg: "A senha é obrigatorio."})
        }

// Checar se usuario existe

    const user = await User.findOne({ email:email })

    if (!user){
         return res.status(404).json({msg: "Usuario nao encontrado."})
}

// Checar se a senha existe

    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword){
        return res.status(422).json({msg: "Senha incorreta."})
    }

    try {

        const secret = process.env.SECRET

        const token = jwt.sign(
        {
            id: user._id
        },
        secret,
     )

        res.status(200).json({ msg: 'Autenticação realizada', token })

    } catch (err) {
        
        res.status(500).json({ msg: "erro no servidor" })
    }
})






const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.4xmb9ur.mongodb.net/?retryWrites=true&w=majority`
    )
    .then(() => {
    app.listen(8000)
    console.log("Conectou ao banco de dados")
}).catch((err) => console.log(err))

