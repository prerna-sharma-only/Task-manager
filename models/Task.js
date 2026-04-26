const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  title: String,
  completed: { type: Boolean, default: false }
});

module.exports = mongoose.model('Task', taskSchema);