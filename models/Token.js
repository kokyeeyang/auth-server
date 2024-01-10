const mongoose = require('mongoose')

const tokenSchema = new mongoose.Schema({
    refreshToken:{type:String, required:true},
    ipAddress:{type:String, required:true},
    userAgent:{type:String, required:true},
    isValid:{type:Boolean, default:true},
    user: {
        type: mongoose.Types.ObjectId,
        ref: 'User',
        required: true,
    },
},
{ timestamps: true, toJSON: { virtuals: true }, toObject: { virtuals: true } }
)

module.exports = mongoose.model('Token', tokenSchema)