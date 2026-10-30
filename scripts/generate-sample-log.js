const fs = require('fs');
const path = require('path');
const { generate } = require('../src/sampleLog');

const out = path.join(__dirname, '..', 'samples', 'access.log');
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, generate().join('\n') + '\n');
console.log('Sample log written to', out);
