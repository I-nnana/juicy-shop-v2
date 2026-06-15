import { type Request, type Response, type NextFunction } from 'express'
import * as models from '../models/index'

// VULNERABILITY 1 - SQL Injection
// User input is directly concatenated into SQL query without sanitization
export function getOrderById () {
  return (req: Request, res: Response, next: NextFunction) => {
    const orderId = req.query.orderId  // user-controlled input
    models.sequelize.query(
      `SELECT * FROM Orders WHERE id = '${orderId}'` // vulnerable line
    )
      .then(([orders]: any) => {
        res.json(orders)
      }).catch((error: Error) => {
        next(error)
      })
  }
}

// VULNERABILITY 2 - SQL Injection on user email
// Same pattern, different vector - searching by email without sanitization
export function getUserByEmail () {
  return (req: Request, res: Response, next: NextFunction) => {
    const email = req.query.email  // user-controlled input
    models.sequelize.query(
      `SELECT * FROM Users WHERE email = '${email}'` // vulnerable line
    )
      .then(([users]: any) => {
        res.json(users)
      }).catch((error: Error) => {
        next(error)
      })
  }
}
