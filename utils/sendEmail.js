const nodemailer = require('nodemailer')
const nodemailerConfig = require('./nodemailerConfig')

const sendEmail = async({to,subject,html}) => {
    let testAccount = await nodemailer.createTestAccount()
    const transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        auth: {
            user: 'sven.smitham@ethereal.email',
            pass: 'ubYF76XZTV7UUgTwck'
        }
    });

    return transporter.sendMail({
        from: '"YYK 👻" <mech@gmail.com>', // sender address
        to,
        subject,
        html
    });
}

module.exports = sendEmail