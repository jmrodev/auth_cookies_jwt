import express from 'express'
import { PORT, SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'

const app = express()
app.set('view engine', 'ejs')
app.use(express.json())
app.use(cookieParser())

app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }

  try {
    const data = jwt.verify(token, SECRET_JWT_KEY)
    req.session.user = data
  } catch {}
  next()
})

app.get('/', (req, res) => {
  const { user } = req.session
  res.render('index')
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  console.log(req.body)

  try {
    const user = await UserRepository.login({ username, password })
    const token = jwt.sign(
      { id: user.id, username: user.username },
      SECRET_JWT_KEY,
      { expiresIn: '1h' }
    )
    res
      .cookie('access_token', token, {
        httpOnly: true,
        maxAge: 1000 * 60 * 60,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
      })
      .send({ user })
  } catch (error) {
    res.status(401).send(error.message)
  }
})

app.post('/register', async (req, res) => {
  // aqui un try catch para manejar errores
  const { username, password } = req.body
  console.log(req.body)

  try {
    const id = await UserRepository.create({ username, password })
    res.status(201).json({ id })
  } catch (error) {
    // normalmente no es bueno enviar el error directamente
    // al cliente ver video "error como un senior" de midudev
    res.status(400).json({ error: error.message })
  }
})
app.post('/logout', (req, res) => {
  res.clearCookie('access_token').send('Logged out')
})

app.get('/protected', (req, res) => {
  const { user } = req.session
  if (!user) return res.status(403).send('Unauthorized')
  res.render('protected', user)
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
