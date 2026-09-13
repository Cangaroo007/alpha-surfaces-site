'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { normalise, addressLine, subfields, pipedrivePayload, titleCase } = require('./address.js');

// Every case below is real data from the 13 Sep backfill run.
const cases = [
  // [unit, street, expected line, note]
  ['9',    '9 Sunnymede Lane',  '9 Sunnymede Lane',   'repeated house number'],
  ['37',   '37 Hibiscus Drive', '37 Hibiscus Drive',  'repeated'],
  ['99',   '99 Springfield Avenue', '99 Springfield Avenue', 'repeated'],
  ['54',   '54 Margaret St',    '54 Margaret St',     'repeated'],
  ['94',   'Ring Street',       '94 Ring Street',     'unit is house number'],
  ['18',   'Jarrah Street',     '18 Jarrah Street',   'unit is house number'],
  ['2',    '11 Sundew St',      '2/11 Sundew St',     'genuine unit'],
  ['4',    '13/Commerce Ave',   '4/13/Commerce Ave',  'street already has slash - kept'],
  ['',     '8 Cathne Street',   '8 Cathne Street',    'street only'],
  ['1',    '7 Hale St,',        '1/7 Hale St',        'trailing comma stripped'],
  ['Unit 547', '547/61 Noosa Springs Drive', '547/61 Noosa Springs Drive', 'no triple'],
  ['8 Toorumbee drive', '8 Toorumbee drive', '8 Toorumbee drive', 'identical'],
];

for (const [unit, street, expected, note] of cases) {
  test(`${note}: "${unit}" + "${street}"`, () => {
    assert.strictEqual(addressLine(unit, street).line, expected);
  });
}

test('suburb case is normalised', () => {
  assert.strictEqual(titleCase('HERMIT PARK'), 'Hermit Park');
  assert.strictEqual(titleCase('allenstown'), 'Allenstown');
  assert.strictEqual(titleCase('West Wyalong '), 'West Wyalong');
  assert.strictEqual(titleCase("o'connor"), "O'Connor");
});

test('a clean record formats and passes', () => {
  const r = normalise({ unit: '9', street: '9 Sunnymede Lane', suburb: 'berry', state: 'nsw', postcode: '2535' });
  assert.strictEqual(r.formatted, '9 Sunnymede Lane, Berry NSW 2535, Australia');
  assert.ok(r.ok);
});

test('state typed into the postcode box is caught, not guessed', () => {
  const r = normalise({ unit: '', street: '1 Smith St', suburb: 'Nowhere', state: 'VIC', postcode: 'VIC ' });
  assert.ok(!r.ok);
  assert.ok(r.problems.some(p => p.includes('postcode')));
});

test('unresolvable unit is flagged rather than guessed', () => {
  const r = normalise({ unit: '90/1016', street: '90 swain st', suburb: 'Gungahlin', state: 'ACT', postcode: '2912' });
  assert.ok(!r.ok, 'should not silently write a guess');
});

test('subfields split a unit address', () => {
  assert.deepStrictEqual(subfields('2/11 Sundew St'),
    { subpremise: '2', street_number: '11', route: 'Sundew St' });
});

test('subfields split a plain street address', () => {
  assert.deepStrictEqual(subfields('94 Ring Street'),
    { subpremise: '', street_number: '94', route: 'Ring Street' });
});

test('subfields handle a lettered house number', () => {
  assert.deepStrictEqual(subfields('12a Hale St'),
    { subpremise: '', street_number: '12a', route: 'Hale St' });
});

test('subfields leave a lot address whole', () => {
  assert.deepStrictEqual(subfields('Lot 3 Bli Bli Road'),
    { subpremise: '', street_number: '', route: 'Lot 3 Bli Bli Road' });
});

test('pipedrive payload carries every component', () => {
  const n = normalise({ unit: '2', street: '11 Sundew St', suburb: 'HERMIT PARK', state: 'qld', postcode: '4812' });
  const p = pipedrivePayload('KEY', n);
  assert.strictEqual(p.KEY_subpremise, '2');
  assert.strictEqual(p.KEY_street_number, '11');
  assert.strictEqual(p.KEY_route, 'Sundew St');
  assert.strictEqual(p.KEY_locality, 'Hermit Park');
  assert.strictEqual(p.KEY_admin_area_level_1, 'QLD');
  assert.strictEqual(p.KEY_postal_code, '4812');
  assert.strictEqual(p.KEY_country, 'Australia');
  assert.strictEqual(p.KEY, '2/11 Sundew St, Hermit Park QLD 4812, Australia');
});

// --- cases the 13 Sep dry run flagged -------------------------------------

test('unit already holds the pair: "4/13" + "Commerce Ave"', () => {
  const n = normalise({ unit: '4/13', street: 'Commerce Ave', suburb: 'WARANA', state: 'QLD', postcode: '4575' });
  assert.strictEqual(n.line, '4/13 Commerce Ave');
  assert.ok(n.ok, n.problems.join('; '));
  assert.deepStrictEqual(subfields(n.line),
    { subpremise: '4', street_number: '13', route: 'Commerce Ave' });
});

test('trailing space does not break the pair: "2/34 " + "George St"', () => {
  const n = normalise({ unit: '2/34 ', street: 'George St', suburb: 'Alexandra Headland', state: 'QLD', postcode: '4572' });
  assert.strictEqual(n.line, '2/34 George St');
  assert.ok(n.ok, n.problems.join('; '));
});

test('shifted fields are reported, not written', () => {
  const n = normalise({ unit: '3/334', street: 'Bay', suburb: 'Street', state: 'NSW', postcode: '2216' });
  assert.ok(!n.ok);
  assert.ok(n.problems.some(p => /shifted one across/.test(p)), n.problems.join('; '));
});

test('an ambiguous unit is still refused', () => {
  const n = normalise({ unit: '1-9, 8', street: 'Mulligan St', suburb: 'Manoora', state: 'QLD', postcode: '4870' });
  assert.ok(!n.ok);
});

test('missing postcode is still refused', () => {
  const n = normalise({ unit: '78', street: 'Olive Avenue ', suburb: 'Mildura ', state: 'VIC', postcode: 'VIC ' });
  assert.ok(!n.ok);
  assert.ok(n.problems.some(p => /postcode/.test(p)));
});

test('shouting street is tidied', () => {
  const n = normalise({ unit: '', street: '51 KITCHENER AVE', suburb: 'Earlwood', state: 'NSW', postcode: '2206' });
  assert.strictEqual(n.line, '51 Kitchener Ave');
});

test('all-lowercase street is tidied', () => {
  const n = normalise({ unit: '', street: '40 carnation road', suburb: 'Manly West', state: 'QLD', postcode: '4179' });
  assert.strictEqual(n.line, '40 Carnation Road');
});

test('mixed-case street is left alone', () => {
  const n = normalise({ unit: '', street: '17 Armstrong st', suburb: 'Hermit Park', state: 'QLD', postcode: '4812' });
  assert.strictEqual(n.line, '17 Armstrong st');
});

test('U-prefix and number range split correctly', () => {
  assert.deepStrictEqual(subfields('U7 13-15 Pacific Tce'),
    { subpremise: '7', street_number: '13-15', route: 'Pacific Tce' });
});

test('lot address still survives', () => {
  const n = normalise({ unit: '', street: 'Lot 442 (6) Worona Lane', suburb: 'Bohle Plains', state: 'QLD', postcode: '4817' });
  assert.strictEqual(n.line, 'Lot 442 (6) Worona Lane');
  assert.ok(n.ok);
});
