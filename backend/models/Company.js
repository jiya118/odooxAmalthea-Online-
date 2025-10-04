const mongoose = require('mongoose');
const CompanySchema = new mongoose.Schema({
    name: { type: String, required: true },
    baseCurrency: { type: String, required: true }, // e.g., 'USD', 'EUR'
    createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('Company', CompanySchema);