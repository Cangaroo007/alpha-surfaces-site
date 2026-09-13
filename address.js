'use strict';
/**
 * Australian street address normaliser.
 *
 * The Unit / House No. field on /order-sample is required, so people fill it
 * whether or not they live in a unit. The three things they actually do:
 *
 *   unit "9"    street "9 Sunnymede Lane"   - repeated the house number
 *   unit "94"   street "Ring Street"        - unit IS the house number
 *   unit "2"    street "11 Sundew St"       - a genuine unit
 *
 * Joining those with "/" unconditionally produced "9/9 Sunnymede Lane", which
 * is not a real address and which Google would not geocode - which is why the
 * structured subfields came back empty on 68 of 73 records.
 *
 * Anything this cannot resolve confidently is flagged rather than guessed. A
 * wrong address is worse than a missing one: it buys a label and posts a box
 * to a stranger.
 */

const STATES = ['ACT', 'NSW', 'NT', 'QLD', 'SA', 'TAS', 'VIC', 'WA'];

/** Words that stay capitalised or lowercase when title-casing a suburb. */
const KEEP_UPPER = new Set(['NSW','QLD','VIC','SA','WA','NT','ACT','TAS','PO','GPO']);
const KEEP_LOWER = new Set(['of','the','on','in','de','la','upon']);

function squash(s) {
  return String(s ?? '')
    .replace(/ /g, ' ')      // non-breaking spaces from copy-paste
    .replace(/\s+/g, ' ')
    .replace(/\s*,\s*/g, ', ')
    .replace(/,\s*,+/g, ', ')     // "Hale St,," -> "Hale St,"
    .replace(/^[,\s]+|[,\s]+$/g, '')
    .trim();
}

function titleCase(s) {
  return squash(s)
    .toLowerCase()
    .split(' ')
    .map((w, i) => {
      const bare = w.replace(/[^a-z]/gi, '');
      if (KEEP_UPPER.has(bare.toUpperCase()) && bare.length <= 3 && i > 0) return bare.toUpperCase();
      if (i > 0 && KEEP_LOWER.has(bare)) return bare;
      // Hyphenated and apostrophed names: Coolum-Beach, O'Connor
      return w.replace(/(^|[-'’])([a-z])/g, (_, p, c) => p + c.toUpperCase());
    })
    .join(' ');
}

/** "Unit 5" / "U5" / "#5" / "Apt 5" -> "5". Returns '' if nothing useful. */
function cleanUnit(raw) {
  let u = squash(raw).replace(/[.,]+$/, '');
  u = u.replace(/^(unit|apt|apartment|suite|flat|u|no\.?|#)\s*/i, '').trim();
  return u;
}

/**
 * Combine unit and street into one Australian address line.
 * Returns { line, confident, why }.
 */
function addressLine(rawUnit, rawStreet) {
  const unit = cleanUnit(rawUnit);
  let street = squash(rawStreet).replace(/[.,]+$/, '');

  if (!street && !unit) return { line: '', confident: false, why: 'no street or unit' };

  // Street empty, unit carries everything: "12 Smith St" typed into Unit.
  if (!street) {
    return /\d/.test(unit) && /[a-z]{3}/i.test(unit)
      ? { line: unit, confident: true, why: 'street empty, unit held the address' }
      : { line: unit, confident: false, why: 'street empty and unit is not an address' };
  }

  if (!unit) return { line: street, confident: true, why: 'street only' };

  // Identical, or unit repeated as the leading number of street.
  if (unit.toLowerCase() === street.toLowerCase()) {
    return { line: street, confident: true, why: 'unit duplicated street' };
  }
  const leading = street.match(/^(\d+[a-z]?)\b/i);
  if (leading && leading[1].toLowerCase() === unit.toLowerCase()) {
    return { line: street, confident: true, why: 'unit repeated the house number' };
  }

  // Street already carries a unit/number pair — "547/61 Noosa Springs Drive".
  // Adding another prefix makes "547/547/61". Keep the street.
  if (/^\d+[a-z]?\s*\/\s*\d/i.test(street)) {
    return { line: street, confident: true, why: 'street already unit/number' };
  }

  // Unit already holds the whole pair - "4/13" + "Commerce Ave".
  if (/^\d+[a-z]?\s*\/\s*\d+[a-z]?$/i.test(unit) && !leading) {
    return { line: `${unit.replace(/\s*\/\s*/, '/')} ${street}`, confident: true, why: 'unit held the unit/number pair' };
  }

  // Street starts with a house number and unit is a plain number: genuine unit.
  if (leading && /^\d+[a-z]?$/i.test(unit)) {
    return { line: `${unit}/${street}`, confident: true, why: 'unit and house number' };
  }

  // Street has no leading number: the unit IS the house number.
  if (!leading && /^\d+[a-z]?$/i.test(unit)) {
    return { line: `${unit} ${street}`, confident: true, why: 'unit is the house number' };
  }

  // Lot numbers and anything else non-numeric — keep both, flag it.
  if (/^lot\b/i.test(unit) || /^lot\b/i.test(street)) {
    return { line: `${unit} ${street}`.trim(), confident: true, why: 'lot address' };
  }
  return { line: `${unit}/${street}`, confident: false, why: `cannot resolve unit "${unit}"` };
}


/** "51 KITCHENER AVE" -> "51 Kitchener Ave". Leaves numbers and Mc/Mac alone. */
function tidyStreetCase(line) {
  if (!line) return line;
  const letters = line.replace(/[^a-z]/gi, '');
  // Only touch it if it is shouting or entirely lowercase.
  if (letters && letters !== letters.toUpperCase() && letters !== letters.toLowerCase()) return line;
  return titleCase(line).replace(/\bMc([a-z])/g, (_, c) => 'Mc' + c.toUpperCase());
}

/** Full record -> a geocodable one-line address plus explicit subfields. */
function normalise(r) {
  let { line, confident, why } = addressLine(r.unit, r.street);
  line = tidyStreetCase(line);
  const suburb = titleCase(r.suburb);
  const state = squash(r.state).toUpperCase();
  const postcode = squash(r.postcode).replace(/[^\d]/g, '');

  const STREET_WORDS = /^(st|street|rd|road|ave|avenue|dr|drive|cct|circuit|cr|cres|crescent|ct|court|pl|place|lane|ln|pde|parade|tce|terrace|way|hwy|highway|esp|esplanade|blvd|boulevard)$/i;

  const problems = [];
  if (!line) problems.push('no street address');
  if (!suburb) problems.push('no suburb');
  if (STREET_WORDS.test(suburb))
    problems.push(`suburb is "${suburb}" - the address fields look shifted one across`);
  if (!/^\d{4}$/.test(postcode)) problems.push(`postcode "${squash(r.postcode)}"`);
  if (!STATES.includes(state)) problems.push(`state "${squash(r.state)}"`);
  if (!confident) problems.push(why);

  return {
    line, suburb, state, postcode,
    formatted: [line, `${suburb} ${state} ${postcode}`.trim(), 'Australia']
      .filter(Boolean).join(', '),
    ok: problems.length === 0,
    problems,
    why
  };
}

/**
 * Decompose a normalised address line into the structured parts Pipedrive
 * keeps in the subfields of an address custom field.
 *
 *   "2/11 Sundew St"   -> subpremise 2, street_number 11, route "Sundew St"
 *   "94 Ring Street"   ->                street_number 94, route "Ring Street"
 *   "Lot 3 Bli Bli Rd" ->                                  route "Lot 3 Bli Bli Rd"
 *
 * We write these ourselves rather than relying on Google to reverse them out
 * of the string. Google is what failed on the 13 Sep run, and the customer
 * already told us each part on the form - there is nothing to infer.
 */
function subfields(line) {
  const l = squash(line);
  let subpremise = '', street_number = '', route = l;

  const NUM = '\\d+[a-z]?(?:-\\d+[a-z]?)?';
  let m = l.match(new RegExp(`^(${NUM})\\s*/\\s*(${NUM})\\s+(.+)$`, 'i'));
  if (m) {
    subpremise = m[1]; street_number = m[2]; route = m[3];
  } else if ((m = l.match(new RegExp(`^u\\s?(${NUM})\\s+(${NUM})\\s+(.+)$`, 'i')))) {
    subpremise = m[1]; street_number = m[2]; route = m[3];
  } else if ((m = l.match(new RegExp(`^(${NUM})\\s+(.+)$`, 'i')))) {
    street_number = m[1]; route = m[2];
  }
  return { subpremise, street_number, route: squash(route) };
}

/**
 * The exact payload to PUT at a Pipedrive person, given the address field key.
 * Subfield names are Pipedrive's own: <key>_<component>.
 */
function pipedrivePayload(key, n) {
  const sf = subfields(n.line);
  const p = {};
  p[key] = n.formatted;
  p[key + '_subpremise'] = sf.subpremise;
  p[key + '_street_number'] = sf.street_number;
  p[key + '_route'] = sf.route;
  p[key + '_locality'] = n.suburb;
  p[key + '_admin_area_level_1'] = n.state;
  p[key + '_postal_code'] = n.postcode;
  p[key + '_country'] = 'Australia';
  p[key + '_formatted_address'] = n.formatted;
  return p;
}

module.exports = { normalise, addressLine, subfields, tidyStreetCase, pipedrivePayload, titleCase, cleanUnit, STATES };
