=== 970 Design Vue Gravity Forms (Headless) ===
Contributors: 970design
Tags: gravity forms, headless, rest api, vue, astro
Requires at least: 5.8
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/old-licenses/gpl-2.0.html

Secure proxy endpoints for headless Gravity Forms integration with Vue.js and Astro.js frontends.

== Description ==

970 Design Vue Gravity Forms (Headless) provides secure REST API endpoints for using Gravity Forms in a headless WordPress environment. Perfect for decoupled architectures using Vue.js, Astro.js, or other JavaScript frameworks.

**Features:**

* Secure API key authentication
* RESTful endpoints for form schema retrieval and submission
* CORS support with configurable allowed origins
* Full support for all standard Gravity Forms field types
* Multi-file upload support
* SVG file upload capability
* Multi-page/multi-step forms support
* Form validation with field-specific error messages
* Configurable confirmation messages and redirects
* IP address tracking and user agent logging
* Built-in caching for form schemas

== Installation ==

**Requirements:**
* WordPress 5.8 or higher
* PHP 7.4 or higher
* Gravity Forms plugin (active and licensed)

**Installation Steps:**

1. Install plugin from WordPress directory.

2. Activate the plugin through the 'Plugins' menu in WordPress.

3. Navigate to **Settings > GF Headless API** in your WordPress admin.

4. Copy the automatically generated API key (or generate a new one if needed).

5. Configure your allowed origins (one per line).

6. Save your settings.

**Frontend Setup (Vue.js/Astro.js):**

1. Install the required dependencies in your frontend project:
   ```bash
   npm install vue recaptcha-v3
   ```

2. Import and use the GravityForm component in your Vue/Astro project:
   ```vue
   <GravityForm
     endpoint="https://your-wordpress-site.com"
     :form-id="1"
     api-key="your-api-key-here"
     recaptcha-key="your-recaptcha-key-optional"
   />
   ```

3. The component files (`GravityForm.vue` and field components) should be placed in your project's components directory.

== API Endpoints ==

**Get Form Schema**
```
GET /wp-json/gf-headless/v1/forms/{form_id}
```
Headers: `X-API-Key: your-api-key`

Returns the complete form configuration including all fields, validation rules, and settings.

**Submit Form**
```
POST /wp-json/gf-headless/v1/forms/{form_id}/submit
```
Headers: `X-API-Key: your-api-key`
Body: multipart/form-data with form field values

Processes form submission, handles file uploads, validates data, and sends notifications.

== Configuration ==

**API Key**
A secure API key is automatically generated on plugin activation. You can regenerate it at any time from the settings page. The API key is required for all API requests.

**Allowed Origins**
Configure which domains can access your API endpoints. Add one origin per line:
```
https://yoursite.com
http://localhost:4321
```

Use `*` to allow all origins (not recommended for production).

**CORS Settings**
The plugin automatically handles CORS headers based on your allowed origins configuration. Credentials are enabled by default for authenticated requests.

== Frequently Asked Questions ==

= Do I need Gravity Forms installed? =
Yes, this plugin requires an active and licensed installation of Gravity Forms.

= Is the API secure? =
Yes, all endpoints require API key authentication via the `X-API-Key` header. Additionally, you can restrict access by domain using CORS settings.

= Can I use this with React or other frameworks? =
While the included components are built for Vue.js, you can easily adapt them for React, Svelte, or any other JavaScript framework by following the same API patterns.

= How do I handle reCAPTCHA? =
Pass your reCAPTCHA v3 site key to the `recaptcha-key` prop in the GravityForm component. The plugin will automatically verify submissions.

= What happens to form notifications? =
All Gravity Forms notifications configured in the WordPress admin will be sent automatically upon successful form submission.

= Can I customize the form styling? =
Yes, the plugin uses standard Gravity Forms CSS class names, so you can style the forms using your own CSS or adapt Gravity Forms' default styles.

== Changelog ==

= 1.0 =
* Initial release

== Upgrade Notice ==

= 1.0 =
Initial release of the headless Gravity Forms plugin.
