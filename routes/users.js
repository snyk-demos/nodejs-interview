var express = require('express')
var typeorm = require("typeorm");
var mysql = require('mysql')
var childProcess = require('child_process')
var path = require('path')
var fs = require('fs')
var router = express.Router()
module.exports = router

router.get('/search', function (req, res, next) {
  const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'acme'
  })
  const name = req.query.name
  // SQL Injection: user-controlled input concatenated directly into the query string
  const query = "SELECT id, name, address, role FROM users WHERE name = '" + name + "'"
  connection.query(query, function (err, results) {
    connection.end()
    if (err) return next(err)
    return res.json(results)
  })
})

// Command Injection: user-controlled input passed to a shell
router.get('/ping', function (req, res, next) {
  const host = req.query.host
  childProcess.exec('ping -c 1 ' + host, function (err, stdout, stderr) {
    if (err) return next(err)
    return res.send(stdout)
  })
})

// Path Traversal: user-controlled input used to build a filesystem path
router.get('/avatar', function (req, res, next) {
  const file = req.query.file
  const fullPath = path.join(__dirname, 'uploads', file)
  fs.readFile(fullPath, 'utf8', function (err, data) {
    if (err) return next(err)
    return res.send(data)
  })
})

// Reflected XSS: user-controlled input written into an HTML response without encoding
router.get('/profile', function (req, res, next) {
  const name = req.query.name
  res.setHeader('Content-Type', 'text/html')
  const html = '<html><body><h1>Profile</h1>' +
    '<p>Results for: ' + name + '</p>' +
    '</body></html>'
  return res.send(html)
})

router.get('/', async (req, res, next) => {
  const mongoConnection = typeorm.getConnection('mysql')
  const repo = mongoConnection.getRepository("Users")
  // hard-coded getting account id of 1
  // as a rpelacement to getting this from the session and such
  // (just imagine that we implemented auth, etc)
  const results = await repo.find({ id: 1 })
  // Log Object's where property for debug reasons:
  console.log('The Object.where property is set to: ', {}.where)
  console.log(results)
  return res.json(results)
})

router.post('/', async (req, res, next) => {
  try {
    const mongoConnection = typeorm.getConnection('mysql')
    const repo = mongoConnection.getRepository("Users")
    const user = {}
    user.name = req.body.name
    user.address = req.body.address
    user.role = req.body.role
    const savedRecord = await repo.save(user)
    console.log("Post has been saved: ", savedRecord)
    return res.sendStatus(200)
  } catch (err) {
    console.error(err)
    console.log({}.where)
    next();
  }
})
