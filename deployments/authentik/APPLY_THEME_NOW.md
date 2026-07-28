# Apply Accessibility Theme RIGHT NOW

The CSS file is ready and accessible. Here's how to apply it instantly:

## Method 1: Browser Console (Instant - 5 seconds)

1. You're already logged into Authentik at http://localhost:9000
2. Press **F12** (or **Cmd+Option+I** on Mac) to open Developer Tools
3. Click the **Console** tab
4. Paste this JavaScript and press Enter:

```javascript
(function() {
    var link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = '/static/dist/afterdark-accessibility.css';
    document.head.appendChild(link);
    console.log('✓ Accessibility theme applied!');
})();
```

5. The background image should disappear instantly!

## Method 2: Bookmarklet (Permanent - Click to toggle)

1. Create a new bookmark in your browser
2. Name it: **"AfterDark Theme"**
3. For the URL, paste this:

```javascript
javascript:(function(){var l=document.createElement('link');l.rel='stylesheet';l.href='/static/dist/afterdark-accessibility.css';document.head.appendChild(l);})();
```

4. Save the bookmark
5. Click it whenever you visit Authentik to apply the theme

## Method 3: Browser Extension (Best - Always On)

### For Chrome/Brave:
1. Install "User CSS" or "Stylus" extension
2. Add a new style for `http://localhost:9000`
3. Import URL: `/static/dist/afterdark-accessibility.css`

### For Firefox:
1. Install "Stylus" add-on
2. Click "Write new style"
3. Add rule for `http://localhost:9000`
4. Import URL: `/static/dist/afterdark-accessibility.css`

## Method 4: Permanent (Via Authentik UI)

If you want it built into Authentik permanently:

1. Admin Interface → System → Brands → authentik Default
2. Scroll to "Customisation"
3. In the **"Custom CSS"** field, paste:

```css
@import url('/static/dist/afterdark-accessibility.css');
```

4. Click **Update**

## What You Should See

**Before**: Colorful background image, busy visuals
**After**: Solid dark gray (#1a1a1a), clean, minimal

## Quick Test

The CSS file is live at:
http://localhost:9000/static/dist/afterdark-accessibility.css

You can test it's working by visiting that URL in your browser - you should see the CSS code.

## Need Help?

If none of these work, let me know and I'll find another approach!
