// Unit tests for the AI bot's code-level safeguards (bots/ember-bot.js).

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mentionsBeingMinor, sanitizeReply, loadRules, CORE_RULES } = require('../bots/ember-bot.js');

test('detects statements of being under 18 (en/de/fr/it)', () => {
  for (const s of [
    "i'm 15", 'Im 16 btw', 'I am only 14', '15 years old here', '16yo', '17 y/o', 'asl? 15 f',
    "I'm a minor", "I'm underage", "i'm in high school", "I'm in 9th grade",
    'ich bin 16', 'ich bin erst 15', 'bin 17 jahre alt', "j'ai 15 ans", 'ho 16 anni',
  ]) assert.ok(mentionsBeingMinor(s), s);
});

test('does not flag adults or unrelated numbers', () => {
  for (const s of [
    "I'm 25", "I'm 18", 'I am 34 years old', "I'm 5 minutes late", "I'm 6 feet tall",
    'we met 15 years ago? no, 3', 'ich bin 30', "j'ai 40 ans", 'the 16 bus', "I'm in college",
  ]) assert.ok(!mentionsBeingMinor(s), s);
});

test('replies are plain text and fit the message limit', () => {
  assert.equal(sanitizeReply('**Hi** there `you`'), 'Hi there you');
  assert.equal(sanitizeReply('<think>secret</think>Hello!'), 'Hello!');
  const long = sanitizeReply('This is a sentence. '.repeat(40));
  assert.ok(long.length <= 280, `length ${long.length}`);
  assert.ok(long.endsWith('.'));
});

test('core safety rules are always appended after the editable rules', () => {
  const sys = loadRules(['jazz', 'rain']);
  assert.ok(sys.includes('jazz, rain'), 'keywords substituted');
  assert.ok(sys.includes('"jazz"') && !sys.includes('{first_keyword}'), 'first keyword substituted');
  assert.ok(loadRules([]).includes('"none"'), 'no keywords → "none"');
  assert.ok(sys.endsWith(CORE_RULES), 'core rules come last');
  assert.match(CORE_RULES, /Never claim or pretend to be human/);
  assert.match(CORE_RULES, /18 or older/);
});
