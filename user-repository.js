import DBLocal from 'db-local'
import crypto from 'crypto'
import bcrypt from 'bcrypt'
import { SALTROUNDS } from './config.js'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})

export class UserRepository {
  //  a futuro : inyeccion de dependencias ,constructor,no static
  static async create({ username, password }) {
    // 1. validar los datos
    Validation.username(username)
    Validation.password(password)

    // 2. verificar si el usuario no existe
    const user = User.findOne({ username })
    if (user) {
      throw new Error('User already exists')
    }

    const id = crypto.randomUUID()

    // 3. hashear la contraseña
    const hashedPassword = await bcrypt.hash(password, SALTROUNDS)

    User.create({
      _id: id,
      username,
      password: hashedPassword,
    }).save()

    return id
  }

  static async login({ username, password }) {
    // 1. validar los datos
    Validation.username(username)
    Validation.password(password)

    // 2. verificar si el usuario existe
    const user = User.findOne({ username })
    if (!user) {
      throw new Error('User does not exist')
    }

    // 3. verificar si la contraseña es correcta
    const isPasswordCorrect = await bcrypt.compare(password, user.password)

    if (!isPasswordCorrect) {
      throw new Error('Password is incorrect')

      const { password: _, ...publicUser } = user
    }

    // mejor es devolver asi
    // return {
    //   username: user.username,
    //   id: user._id,
    //
    // }

    // esto es para devolver solo un campo y siendo explicito para un caso que no queremos devolver( password)
    return user
  }
}
class Validation {
  static username(username) {
    // validaciones .Usar zod
    if (typeof username !== 'string') {
      throw new Error('The username must be a string')
    }
    if (username.length < 3) {
      throw new Error('The username must be at least 3 characters long')
    }
  }

  static password(password) {
    if (typeof password !== 'string') {
      throw new Error('The password must be a string')
    }
    if (password.length < 3) {
      throw new Error('The password must be at least 3 characters long')
    }
  }
}
