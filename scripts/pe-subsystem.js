'use strict';
// Marks a Windows .exe as a windowed program (the "GUI" subsystem) so that starting it opens no console window.
// Node supports this: without a console its standard output simply goes nowhere, and CORS Bridge writes a log file.
const SUBSYSTEM = { gui: 2, console: 3 };

// Changes the buffer in place and returns the previous subsystem number.
function setSubsystem(buf, kind = 'gui') {
  if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) throw new Error('Not a Windows program (no MZ header)');
  const pe = buf.readUInt32LE(0x3c);
  if (pe + 24 + 70 > buf.length || buf.readUInt32LE(pe) !== 0x00004550) throw new Error('Not a Windows program (no PE header)');
  const optional = pe + 24;
  const magic = buf.readUInt16LE(optional);
  if (magic !== 0x10b && magic !== 0x20b) throw new Error('Unknown PE optional header');
  const offset = optional + 68; // same place in 32- and 64-bit programs
  const before = buf.readUInt16LE(offset);
  buf.writeUInt16LE(SUBSYSTEM[kind], offset);
  return before;
}

module.exports = { setSubsystem, SUBSYSTEM };
