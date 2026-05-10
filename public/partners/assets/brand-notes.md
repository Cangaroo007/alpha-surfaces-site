# Partner Brand Notes

Observed from each partner's live HTML / CSS on 10 May 2026. Hex codes are the dominant brand-accent / surface colours seen in the site's stylesheet; treat them as a starting point and confirm with the partner if exact-match colour is required.

## 1. Dream Doors Kitchens — dreamdoorskitchens.com.au

- Primary: `#FB8E28` (orange — Elementor accent / button colour)
- Secondary: `#373737` (charcoal — body text / nav)
- Supporting neutrals: `#FFFFFF`, `#ECECEC`
- Font family: **Sofia Pro** (served via Adobe Typekit kit `lks5yyv`), sans-serif fallback
- Logo file: `ddk-Logo-pos-RGB@2x.png` (positive RGB lockup, 554×70)

## 2. Impala Kitchens — impalakitchens.com.au

- Primary: `#F7931D` (Impala orange — by far the dominant brand colour in the theme stylesheet)
- Secondary: `#333333` (near-black for headings/text)
- Supporting neutrals: `#FFFFFF`, `#E2E2E2`, `#EEEEEE`
- Accent (occasional): `#FE7700` / `#FC7E04`
- Fonts:
  - Headings: **Bebas Neue Regular** (`BebasNeueRegular`, fallback Arial / Helvetica)
  - Body: **Arial, Helvetica, sans-serif**

## 3. Dimension Stone — dimensionstone.com.au

- Primary: `#B4580C` (warm copper / terracotta accent used on CTAs)
- Secondary: `#111111` (near-black headings) and `#131313` (dark UI)
- Supporting neutrals: `#FFFFFF`, `#FAFAFA`, `#E7E7E7` (rule lines), `#F4F4F4`
- Fonts (Webflow site):
  - Display / headings: **Funnel Display**, sans-serif
  - Body: **Montserrat**, sans-serif
  - Fallback stack uses `Helvetica Neue, Helvetica, Ubuntu, Segoe UI, Verdana`

## 4. Hammertime Kitchens — hammertimekitchens.com.au

- Primary: `#EA7D00` (Hammertime orange — main brand accent)
- Secondary: `#000000` (black headings and footer)
- Supporting accents: `#FBAC15`, `#FC9F00`, `#E89300` (orange family used for buttons / highlights)
- Supporting neutrals: `#FFFFFF`, `#BBBBBB`, `#A1A1A1`
- Fonts (Google Fonts):
  - Headings / display: **Raleway**, sans-serif
  - Body: **Lato**, sans-serif
  - Icon font: FontAwesome

---

### Notes on assets downloaded

| Company | Logo | Hero | Extras |
|---|---|---|---|
| Dream Doors Kitchens | `ddk-logo.png` (554×70 PNG, transparent) | `ddk-hero.jpg` (1424×512 — Sunshine Coast page hero) | — |
| Impala Kitchens | `impala-logo.png` (197×151, re-encoded from source JPG) | `impala-hero.jpg` (1920×955 home banner) | `impala-awards.png` (300×300 — KBDi 2023 Winner badge — representative; full award wall on /about) |
| Dimension Stone | `dimension-logo.png` (1171×150 horizontal lockup, black on white) | `dimension-hero.jpg` (1500×843 showroom/benchtop image) | — |
| Hammertime Kitchens | `hammertime-logo.png` (462×92 PNG, transparent) | `hammertime-hero.jpg` (2560×800 home slider — kitchen install) | `hammertime-outdoor.jpg` (1159×1488 — Instagram @hammertimekitchens feed image) |

The Impala logo on the live site is served as a JPEG (`logo.jpg`); it has been re-encoded to PNG to match the requested filename. If a transparent / vector version is required, request from Impala directly.

The Hammertime outdoor image was pulled from the Instagram feed embedded on the home page (signed Instagram CDN URL). Instagram CDN URLs expire, so re-download rather than hot-linking.
