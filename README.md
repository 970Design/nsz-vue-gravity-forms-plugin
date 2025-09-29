# What is the Vue Gravity Forms Plugin?

This is a WordPress plugin that provides secure proxy endpoints for headless Gravity Forms integration; and can be used in conjunction with the companion [Vue Gravity Forms](https://www.npmjs.com/package/@970design/vue-gravity-forms) package to render and process Gravity Forms in a headless WordPress environment.

## Features

- Secure API key authentication
- RESTful endpoints for form schema retrieval and submission
- CORS support with configurable allowed origins
- Full support for all standard Gravity Forms field types
- Multi-file upload support
- SVG file upload capability
- Multipage/multi-step forms support
- Form validation with field-specific error messages
- Configurable confirmation messages and redirects
- IP address tracking and user agent logging
- Built-in caching for form schemas

## Requirements

- WordPress 5.8 or higher
- PHP 7.4 or higher
- Gravity Forms plugin (active and licensed)

## Installation

1. Install plugin from WordPress directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Navigate to **Settings > GF Headless API** in your WordPress admin
4. Copy the automatically generated API key (or generate a new one if needed)
5. Configure your allowed origins (one per line)
6. Save your settings

### Frontend Setup (Vue.js/Astro.js)

See the companion [Vue Gravity Forms](https://www.npmjs.com/package/@970design/vue-gravity-forms) package for instructions on how to set up the frontend component.

## API Endpoints

### Get Form Schema

```bash
GET /wp-json/gf-headless/v1/forms/{form_id}
Headers: `X-API-Key: your-api-key`
```

Returns the complete form configuration including all fields, validation rules, and settings.

### Submit Form

```bash
POST /wp-json/gf-headless/v1/forms/{form_id}/submit
Headers: `X-API-Key: your-api-key`
Body: multipart/form-data with form field values
```

Processes form submission, handles file uploads, validates data, and sends notifications.

## Configuration

### API Key
A secure API key is automatically generated on plugin activation. You can regenerate it at any time from the settings page. The API key is required for all API requests.

### Allowed Origins
Configure which domains can access your API endpoints. Add one origin per line:

```
https://yoursite.com http://localhost:4321
```

### CORS Settings
The plugin automatically handles CORS headers based on your allowed origins' configuration. Credentials are enabled by default for authenticated requests.

**NOTE: CORS must also be configured at your host to allow requests from your frontend domain in addition to this plugin's settings.**

## FAQ

**Do I need Gravity Forms installed?**
Yes, this plugin requires an active and licensed installation of Gravity Forms.

**Is the API secure?**
Yes, all endpoints require API key authentication via the `X-API-Key` header. Additionally, you can restrict access by domain using CORS settings.

**Can I use this with React or other frameworks?**
While the included components are built for Vue.js, you can easily adapt them for React, Svelte, or any other JavaScript framework by following the same API patterns.

**How do I handle reCAPTCHA?**
Pass your reCAPTCHA v3 site key to the `recaptcha-key` prop in the GravityForm component. The plugin will automatically verify submissions.

**What happens to form notifications?**
All Gravity Forms notifications configured in the WordPress admin will be sent automatically upon successful form submission.

**Can I customize the form styling?**
Yes, the plugin uses standard Gravity Forms CSS class names, so you can style the forms using your own CSS or adapt Gravity Forms' default styles.

## License

GPLv2 or later

## Credits

The development of this package is sponsored by [970 Design](https://970design.com), a creative agency based in Vail, Colorado.  If you need help with your headless WordPress project, please don't hesitate to [reach out](https://970design.com/reach-out/).