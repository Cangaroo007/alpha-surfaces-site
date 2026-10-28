'use strict';
// The lead note's stonemason line (ADR 0065). sprintrep's Requests inbox reads this line, so its
// wording is a contract: change it here and in sprintrep's stonemasonFromNote together.
const { test } = require('node:test');
const assert = require('node:assert');
const { stonemasonNote } = require('./pipedrive.js');

test('a picked company carries its Pipedrive org id', () => {
  assert.strictEqual(
    stonemasonNote({ stonemason_status: 'yes', stonemason_name: 'Ace Stone', stonemason_org_id: '4412' }),
    'Stonemason: Ace Stone (linked, org 4412)<br>',
  );
});

test('typed, unnamed, refer, unsure, decline and blank', () => {
  assert.strictEqual(
    stonemasonNote({ stonemason_status: 'yes', stonemason_name: 'Bob <B>' }),
    'Stonemason: Bob &lt;B&gt; — NOT MATCHED, please identify and link<br>',
  );
  assert.strictEqual(stonemasonNote({ stonemason_status: 'yes' }), 'Stonemason: says they have one, none named<br>');
  assert.strictEqual(stonemasonNote({ stonemason_status: 'no' }), 'Stonemason: NONE — asked to be connected with one<br>');
  assert.match(stonemasonNote({ stonemason_status: 'unsure' }), /not sure yet/);
  assert.match(stonemasonNote({ stonemason_status: 'decline' }), /preferred not to say/);
  assert.strictEqual(stonemasonNote({}), '');
  // A non-numeric id is not trusted as a link.
  assert.match(stonemasonNote({ stonemason_status: 'yes', stonemason_name: 'X', stonemason_org_id: 'abc' }), /NOT MATCHED/);
});
