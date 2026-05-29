"""Module fingerprint database for passive Odoo module detection.

Each fingerprint maps an observable artifact (CSS class prefix, model name,
route, bundle name, HTML class) to the Odoo module that produces it.
"""

# CSS class prefix → module name(s)
# In Odoo, CSS classes follow the pattern o_{module}_{feature}
CSS_CLASS_PREFIXES = {
    # Core / Website
    "o_website_": ["website"],
    "o_web_editor_": ["web_editor"],
    "o_portal_": ["portal"],
    "o_wauth_": ["auth_signup"],
    "o_auth_oauth_": ["auth_oauth"],
    "o_oauth_": ["auth_oauth"],
    # E-Commerce
    "o_wsale_": ["website_sale"],
    "o_website_sale_": ["website_sale"],
    "o_shop_": ["website_sale"],
    "o_website_customer_": ["website_customer"],
    "o_wsale_stock_": ["website_sale_stock"],
    "o_wsale_comparison_": ["website_sale_comparison"],
    "o_wsale_wishlist_": ["website_sale_wishlist"],
    "o_wsale_delivery_": ["website_sale_delivery"],
    "o_wsale_loyalty_": ["website_sale_loyalty"],
    # Events
    "o_wevent_": ["website_event"],
    "o_website_event_": ["website_event"],
    "o_event_": ["event", "website_event"],
    # Forum
    "o_wforum_": ["website_forum"],
    "o_website_forum_": ["website_forum"],
    "o_forum_": ["website_forum"],
    # Blog
    "o_wblog_": ["website_blog"],
    "o_website_blog_": ["website_blog"],
    "o_blog_": ["website_blog"],
    # Slides / eLearning
    "o_wslides_": ["website_slides"],
    "o_website_slides_": ["website_slides"],
    "o_slide_": ["website_slides"],
    "o_wprofile_": ["website_profile", "website_slides"],
    "o_website_profile_": ["website_profile"],
    # CRM
    "o_wcrm_": ["website_crm_partner_assign", "website_crm"],
    "o_website_crm_": ["website_crm"],
    "o_crm_": ["crm"],
    # Appointment / Calendar
    "o_appointment_": ["appointment", "website_appointment"],
    "o_wappointment_": ["website_appointment"],
    "o_website_calendar_": ["website_calendar"],
    # Helpdesk
    "o_whelpdesk_": ["website_helpdesk"],
    "o_helpdesk_": ["helpdesk"],
    # Project
    "o_wproject_": ["website_project"],
    "o_project_": ["project"],
    # HR
    "o_hr_": ["hr"],
    "o_website_hr_": ["website_hr"],
    "o_whr_": ["website_hr_recruitment"],
    "o_hr_recruitment_": ["hr_recruitment"],
    "o_hr_expense_": ["hr_expense"],
    "o_hr_attendance_": ["hr_attendance"],
    "o_hr_holidays_": ["hr_holidays"],
    "o_hr_contract_": ["hr_contract"],
    # Recruitment (Jobs)
    "o_jobs_": ["website_hr_recruitment"],
    # Survey
    "o_survey_": ["survey", "website_slides_survey"],
    # Mail / Discuss
    "o_mail_": ["mail"],
    "o_discuss_": ["mail"],
    "o_mg_": ["mail_group"],
    "o_mail_group_": ["mail_group"],
    # Knowledge
    "o_knowledge_": ["knowledge"],
    # POS
    "o_pos_": ["point_of_sale"],
    # Live Chat
    "o_livechat_": ["im_livechat"],
    "o_im_livechat_": ["im_livechat"],
    # Rating
    "o_rating_": ["rating"],
    # Social
    "o_social_": ["social_media"],
    # Payment
    "o_payment_": ["payment"],
    "o_website_payment_": ["website_payment"],
    # Sign
    "o_sign_": ["sign"],
    # Maintenance
    "o_maintenance_": ["maintenance"],
    # Fleet
    "o_fleet_": ["fleet"],
    # Manufacturing
    "o_mrp_": ["mrp"],
    # Quality
    "o_quality_": ["quality"],
    # Stock / Inventory
    "o_stock_": ["stock"],
    "o_website_stock_": ["website_sale_stock"],
    # Purchase
    "o_purchase_": ["purchase"],
    # Sale
    "o_sale_": ["sale"],
    "o_website_sale_": ["website_sale"],
    # Timesheet
    "o_timesheet_": ["hr_timesheet"],
    "o_hr_timesheet_": ["hr_timesheet"],
    # Planning
    "o_planning_": ["planning"],
    # Spreadsheet
    "o_spreadsheet_": ["spreadsheet"],
    # Gamification
    "o_gamification_": ["gamification"],
    "o_wg_": ["website_gamification"],
    # Mass Mailing
    "o_mass_mailing_": ["mass_mailing"],
    # SMS
    "o_sms_": ["sms"],
    # Snailmail
    "o_snailmail_": ["snailmail"],
    # Marketing
    "o_marketing_": ["marketing_card"],
    # Loyalty
    "o_loyalty_": ["loyalty"],
    # Calendar (generic)
    "o_website_calendar_": ["website_calendar"],
    "o_calendar_": ["calendar"],
    # Membership
    "o_membership_": ["membership"],
    # Lunch
    "o_lunch_": ["lunch"],
    # Expense
    "o_expense_": ["hr_expense"],
    # Marketing Automation
    "o_marketing_automation_": ["marketing_automation"],
    # Event Booth
    "o_event_booth_": ["event_booth"],
    # Event Sale
    "o_event_sale_": ["event_sale"],
    # Event Sponsor
    "o_event_sponsor_": ["event_sponsor"],
    # Event Exhibitor
    "o_event_exhibitor_": ["event_exhibitor"],
    # Event Track
    "o_event_track_": ["event_track"],
    # Event Track Live
    "o_event_track_live_": ["event_track_live"],
    # Event Meet
    "o_event_meet_": ["event_meet"],
    # Event CRM
    "o_event_crm_": ["event_crm"],
    # Sale Coupon
    "o_sale_coupon_": ["sale_coupon"],
    # Sale Loyalty
    "o_sale_loyalty_": ["sale_loyalty"],
    # Sale Gift Card
    "o_sale_gift_card_": ["sale_gift_card"],
    # Sale Rental
    "o_sale_rental_": ["sale_rental"],
    # Sale Subscription
    "o_sale_subscription_": ["sale_subscription"],
    # Sale Timesheet
    "o_sale_timesheet_": ["sale_timesheet"],
    # Sale Project
    "o_sale_project_": ["sale_project"],
    # Account
    "o_account_": ["account"],
    "o_website_account_": ["website_account"],
    # Account Followup
    "o_account_followup_": ["account_followup"],
    # Account Payment
    "o_account_payment_": ["account_payment"],
    # Analytic
    "o_analytic_": ["analytic"],
    # Barcodes
    "o_barcodes_": ["barcodes"],
    # Base Geolocalize
    "o_base_geolocalize_": ["base_geolocalize"],
    # Base Import Module
    "o_base_import_": ["base_import"],
    # Base Setup
    "o_base_setup_": ["base_setup"],
    # Board
    "o_board_": ["board"],
    # Bus
    "o_bus_": ["bus"],
    # Contacts
    "o_contacts_": ["contacts"],
    # Data Recycle
    "o_data_recycle_": ["data_recycle"],
    # Digest
    "o_digest_": ["digest"],
    # Fetchmail
    "o_fetchmail_": ["fetchmail"],
    # Google Calendar
    "o_google_calendar_": ["google_calendar"],
    # Google Gmail
    "o_google_gmail_": ["google_gmail"],
    # HTML Editor
    "o_html_editor_": ["html_editor"],
    # IAP
    "o_iap_": ["iap"],
    # Link Tracker
    "o_link_tracker_": ["link_tracker"],
    # Mail Bot
    "o_mail_bot_": ["mail_bot"],
    # Microsoft Calendar
    "o_microsoft_calendar_": ["microsoft_calendar"],
    # Microsoft Outlook
    "o_microsoft_outlook_": ["microsoft_outlook"],
    # Partner Autocomplete
    "o_partner_autocomplete_": ["partner_autocomplete"],
    # Phone Validation
    "o_phone_validation_": ["phone_validation"],
    # Privacy Lookup
    "o_privacy_lookup_": ["privacy_lookup"],
    # Product
    "o_product_": ["product"],
    # Product Email Template
    "o_product_email_template_": ["product_email_template"],
    # Resource
    "o_resource_": ["resource"],
    # UTM
    "o_utm_": ["utm"],
    # Web Gantt
    "o_web_gantt_": ["web_gantt"],
    # Web Grid
    "o_web_grid_": ["web_grid"],
    # Web Hierarchy
    "o_web_hierarchy_": ["web_hierarchy"],
    # Web Kanban Gauge
    "o_web_kanban_gauge_": ["web_kanban_gauge"],
    # Web Map
    "o_web_map_": ["web_map"],
    # Web PWA
    "o_web_pwa_": ["web_pwa"],
    # Web Settings Dashboard
    "o_web_settings_dashboard_": ["web_settings_dashboard"],
    # Web Tour
    "o_web_tour_": ["web_tour"],
    # Website Google Map
    "o_website_google_map_": ["website_google_map"],
    # Website Livechat
    "o_website_livechat_": ["website_livechat"],
    # Website Membership
    "o_website_membership_": ["website_membership"],
    # Website Rating
    "o_website_rating_": ["website_rating"],
    # Website Sale Comparison
    "o_website_sale_comparison_": ["website_sale_comparison"],
    # Website Sale Digital
    "o_website_sale_digital_": ["website_sale_digital"],
    # Website Sale Gift Card
    "o_website_sale_gift_card_": ["website_sale_gift_card"],
    # Website Sale Picking
    "o_website_sale_picking_": ["website_sale_picking"],
    # Website Sale Product Configurator
    "o_website_sale_product_configurator_": ["website_sale_product_configurator"],
    # Website Sale Slides
    "o_website_sale_slides_": ["website_sale_slides"],
    # Website Sale Stock
    "o_website_sale_stock_": ["website_sale_stock"],
    # Website Sale Wishlist
    "o_website_sale_wishlist_": ["website_sale_wishlist"],
    # Website Slides Forum
    "o_website_slides_forum_": ["website_slides_forum"],
    # Website Slides Survey
    "o_website_slides_survey_": ["website_slides_survey"],
    # HTTP Routing
    "o_http_routing_": ["http_routing"],
    # Base Automation
    "o_base_automation_": ["base_automation"],
    # Base Address Extended
    "o_base_address_extended_": ["base_address_extended"],
    # Base IBAN
    "o_base_iban_": ["base_iban"],
    # Base VAT
    "o_base_vat_": ["base_vat"],
    # Attachment Indexation
    "o_attachment_indexation_": ["attachment_indexation"],
    # Repair
    "o_repair_": ["repair"],
    # Rental
    "o_rental_": ["sale_rental"],
    # Delivery
    "o_delivery_": ["delivery"],
    # Coupon
    "o_coupon_": ["coupon"],
    # Gift Card
    "o_gift_card_": ["gift_card"],
}

# Model name → module name(s)
# data-main-object and other model references map to modules
MODEL_TO_MODULE = {
    "website": ["website"],
    "ir.ui.view": ["base"],
    "ir.ui.menu": ["base"],
    "ir.module.module": ["base"],
    "ir.model": ["base"],
    "ir.model.fields": ["base"],
    "ir.attachment": ["base"],
    "ir.config_parameter": ["base"],
    "res.partner": ["base"],
    "res.users": ["base"],
    "res.company": ["base"],
    "res.country": ["base"],
    "res.currency": ["base"],
    "res.groups": ["base"],
    "res.lang": ["base"],
    "bus.bus": ["bus"],
    "mail.message": ["mail"],
    "mail.thread": ["mail"],
    "mail.channel": ["mail"],
    "mail.notification": ["mail"],
    "mail.alias": ["mail"],
    "mail.template": ["mail"],
    "mail.activity": ["mail"],
    "mail.followers": ["mail"],
    "mail.group": ["mail_group"],
    "crm.lead": ["crm"],
    "crm.team": ["crm"],
    "crm.stage": ["crm"],
    "crm.tag": ["crm"],
    "sale.order": ["sale"],
    "sale.order.line": ["sale"],
    "sale.order.template": ["sale"],
    "account.move": ["account"],
    "account.move.line": ["account"],
    "account.journal": ["account"],
    "account.account": ["account"],
    "account.payment": ["account_payment"],
    "account.invoice": ["account"],
    "purchase.order": ["purchase"],
    "purchase.order.line": ["purchase"],
    "stock.picking": ["stock"],
    "stock.move": ["stock"],
    "stock.quant": ["stock"],
    "stock.warehouse": ["stock"],
    "stock.location": ["stock"],
    "product.product": ["product"],
    "product.template": ["product"],
    "product.category": ["product"],
    "project.project": ["project"],
    "project.task": ["project"],
    "project.tags": ["project"],
    "hr.employee": ["hr"],
    "hr.department": ["hr"],
    "hr.job": ["hr_recruitment"],
    "hr.applicant": ["hr_recruitment"],
    "hr.contract": ["hr_contract"],
    "hr.leave": ["hr_holidays"],
    "hr.leave.type": ["hr_holidays"],
    "hr.expense": ["hr_expense"],
    "hr.expense.sheet": ["hr_expense"],
    "hr.attendance": ["hr_attendance"],
    "hr.timesheet": ["hr_timesheet"],
    "event.event": ["event"],
    "event.registration": ["event"],
    "event.type": ["event"],
    "event.track": ["event_track"],
    "event.sponsor": ["event_sponsor"],
    "event.exhibitor": ["event_exhibitor"],
    "event.booth": ["event_booth"],
    "survey.survey": ["survey"],
    "survey.question": ["survey"],
    "survey.user_input": ["survey"],
    "forum.forum": ["website_forum"],
    "forum.post": ["website_forum"],
    "blog.blog": ["website_blog"],
    "blog.post": ["website_blog"],
    "slide.channel": ["website_slides"],
    "slide.slide": ["website_slides"],
    "slide.slide.partner": ["website_slides"],
    "helpdesk.ticket": ["helpdesk"],
    "helpdesk.team": ["helpdesk"],
    "helpdesk.stage": ["helpdesk"],
    "helpdesk.tag": ["helpdesk"],
    "helpdesk.sla": ["helpdesk"],
    "pos.order": ["point_of_sale"],
    "pos.session": ["point_of_sale"],
    "pos.config": ["point_of_sale"],
    "pos.payment": ["point_of_sale"],
    "mrp.production": ["mrp"],
    "mrp.bom": ["mrp"],
    "mrp.workcenter": ["mrp"],
    "mrp.routing": ["mrp"],
    "maintenance.request": ["maintenance"],
    "maintenance.equipment": ["maintenance"],
    "fleet.vehicle": ["fleet"],
    "fleet.vehicle.log.contract": ["fleet"],
    "quality.check": ["quality"],
    "quality.alert": ["quality"],
    "quality.point": ["quality"],
    "appointment.type": ["appointment"],
    "appointment.booking": ["appointment"],
    "calendar.event": ["calendar"],
    "calendar.attendee": ["calendar"],
    "calendar.recurrence": ["calendar"],
    "knowledge.article": ["knowledge"],
    "knowledge.article.template": ["knowledge"],
    "sign.request": ["sign"],
    "sign.template": ["sign"],
    "planning.slot": ["planning"],
    "planning.role": ["planning"],
    "spreadsheet.dashboard": ["spreadsheet"],
    "spreadsheet.cell": ["spreadsheet"],
    "gamification.badge": ["gamification"],
    "gamification.challenge": ["gamification"],
    "gamification.goal": ["gamification"],
    "mass_mailing.mailing": ["mass_mailing"],
    "mass_mailing.list": ["mass_mailing"],
    "sms.sms": ["sms"],
    "snailmail.letter": ["snailmail"],
    "payment.provider": ["payment"],
    "payment.transaction": ["payment"],
    "payment.token": ["payment"],
    "payment.method": ["payment"],
    "loyalty.program": ["loyalty"],
    "loyalty.card": ["loyalty"],
    "loyalty.reward": ["loyalty"],
    "membership.membership_line": ["membership"],
    "lunch.order": ["lunch"],
    "lunch.product": ["lunch"],
    "lunch.supplier": ["lunch"],
    "im_livechat.channel": ["im_livechat"],
    "im_livechat.chatbot.script": ["im_livechat"],
    "mailing.mailing": ["mass_mailing"],
    "utm.campaign": ["utm"],
    "utm.source": ["utm"],
    "utm.medium": ["utm"],
    "resource.calendar": ["resource"],
    "resource.resource": ["resource"],
    "rating.rating": ["rating"],
    "link.tracker": ["link_tracker"],
    "link.tracker.click": ["link_tracker"],
    "iap.account": ["iap"],
    "iap.enrich.api": ["iap"],
    "digest.tip": ["digest"],
    "data_recycle.model": ["data_recycle"],
    "gamification.karma.tracking": ["gamification"],
    "marketing.activity": ["marketing_automation"],
    "marketing.campaign": ["marketing_automation"],
    "social.post": ["social_media"],
    "social.account": ["social_media"],
    "social.live.post": ["social_media"],
    "repair.order": ["repair"],
    "rental.order": ["sale_rental"],
    "delivery.carrier": ["delivery"],
    "coupon.coupon": ["coupon"],
    "gift.card": ["gift_card"],
    "subscription.plan": ["sale_subscription"],
    "subscription.order": ["sale_subscription"],
    "analytic.account": ["analytic"],
    "analytic.line": ["analytic"],
    "barcodes.barcode_events_mixin": ["barcodes"],
    "phone.validation.mixin": ["phone_validation"],
}

# Route (URL path) → module name(s)
# These are known frontend routes exposed by specific modules
ROUTE_TO_MODULE = {
    # E-Commerce
    "/shop": ["website_sale"],
    "/shop/cart": ["website_sale"],
    "/shop/checkout": ["website_sale"],
    "/shop/confirmation": ["website_sale"],
    "/shop/payment": ["website_sale"],
    "/shop/product": ["website_sale"],
    "/shop/category": ["website_sale"],
    "/shop/pricelist": ["website_sale"],
    "/shop/wishlist": ["website_sale_wishlist"],
    "/shop/comparison": ["website_sale_comparison"],
    "/shop/slides": ["website_sale_slides"],
    "/shop/giftcard": ["website_sale_gift_card", "sale_gift_card"],
    "/shop/confirmation": ["website_sale"],
    # Forum
    "/forum": ["website_forum"],
    "/forum/new": ["website_forum"],
    "/forum/edit": ["website_forum"],
    "/forum/post": ["website_forum"],
    "/forum/tag": ["website_forum"],
    "/forum/user": ["website_forum"],
    # Blog
    "/blog": ["website_blog"],
    "/blog/post": ["website_blog"],
    "/blog/tag": ["website_blog"],
    "/blog/feed": ["website_blog"],
    # Slides / eLearning
    "/slides": ["website_slides"],
    "/slides/slide": ["website_slides"],
    "/slides/channel": ["website_slides"],
    "/slides/tag": ["website_slides"],
    "/slides/embed": ["website_slides"],
    "/slides/all": ["website_slides"],
    "/profile": ["website_profile", "website_slides"],
    "/profile/users": ["website_profile"],
    "/profile/ranks_badges": ["website_profile", "gamification"],
    "/profile/user": ["website_profile"],
    # Events
    "/events": ["website_event"],
    "/event": ["website_event", "event"],
    "/event/register": ["website_event"],
    "/events/register": ["website_event"],
    "/event/ics": ["website_event"],
    # Jobs / Recruitment
    "/jobs": ["website_hr_recruitment"],
    "/jobs/apply": ["website_hr_recruitment"],
    "/jobs/detail": ["website_hr_recruitment"],
    "/jobs/thankyou": ["website_hr_recruitment"],
    # CRM
    "/partners": ["website_crm_partner_assign"],
    "/partners/country": ["website_crm_partner_assign"],
    "/partners/grade": ["website_crm_partner_assign"],
    "/leads": ["crm"],
    "/lead": ["crm"],
    # Appointment
    "/appointment": ["appointment", "website_appointment"],
    "/appointment/schedule": ["appointment"],
    "/appointment/success": ["appointment"],
    # Calendar
    "/calendar": ["calendar", "website_calendar"],
    "/calendar/appointments": ["calendar"],
    "/calendar/join": ["calendar"],
    # Helpdesk
    "/helpdesk": ["helpdesk", "website_helpdesk"],
    "/helpdesk/submit": ["helpdesk", "website_helpdesk"],
    "/helpdesk/ticket": ["helpdesk"],
    "/helpdesk/my_tickets": ["helpdesk"],
    "/helpdesk/rating": ["helpdesk"],
    # Project
    "/project": ["project", "website_project"],
    "/project/task": ["project"],
    "/project/rating": ["project", "rating"],
    "/project/sharing": ["project"],
    "/my/tasks": ["project", "portal"],
    "/my/project": ["project", "portal"],
    # POS
    "/pos": ["point_of_sale"],
    "/pos/ui": ["point_of_sale"],
    "/pos/session": ["point_of_sale"],
    "/pos/restaurant": ["pos_restaurant"],
    "/pos/order": ["point_of_sale"],
    "/pos/receipt": ["point_of_sale"],
    # Survey
    "/survey": ["survey"],
    "/survey/start": ["survey"],
    "/survey/submit": ["survey"],
    "/survey/fill": ["survey"],
    "/survey/print": ["survey"],
    "/survey/results": ["survey"],
    # Mail / Discuss
    "/mail": ["mail"],
    "/mail/read": ["mail"],
    "/mail/track": ["mail"],
    "/mail/view": ["mail"],
    "/mail/unsubscribe": ["mail"],
    "/discuss": ["mail"],
    "/discuss/channel": ["mail"],
    "/discuss/channel/create": ["mail"],
    # Livechat
    "/livechat": ["im_livechat"],
    "/livechat/channel": ["im_livechat"],
    "/livechat/support": ["im_livechat"],
    "/livechat/visitor": ["im_livechat"],
    "/im_livechat": ["im_livechat"],
    "/im_livechat/support": ["im_livechat"],
    "/im_livechat/visitor": ["im_livechat"],
    # WhatsApp
    "/whatsapp": ["whatsapp"],
    # SMS
    "/sms": ["sms"],
    # Payment
    "/payment": ["payment"],
    "/payment/process": ["payment"],
    "/payment/confirmation": ["payment"],
    "/payment/donation": ["payment"],
    "/payment/pay": ["payment"],
    "/payment/transaction": ["payment"],
    # Portal
    "/my": ["portal"],
    "/my/account": ["portal"],
    "/my/orders": ["sale", "portal"],
    "/my/invoices": ["account", "portal"],
    "/my/contracts": ["portal"],
    "/my/documents": ["portal"],
    "/my/projects": ["project", "portal"],
    "/my/tickets": ["helpdesk", "portal"],
    "/my/appointments": ["appointment", "portal"],
    "/my/quotes": ["sale", "portal"],
    "/my/subscriptions": ["sale_subscription", "portal"],
    # Website core
    "/website/info": ["website"],
    "/website/form": ["website"],
    "/website/published": ["website"],
    "/website/attach": ["website"],
    "/website/lang": ["website"],
    "/website/translations": ["website"],
    "/website/sitemap": ["website"],
    "/website/robots": ["website"],
    "/website/google_map": ["website_google_map"],
    "/website_iframe_editor": ["website"],
    "/website_preview": ["website"],
    "/website_force": ["website"],
    "/website/pages": ["website"],
    "/website/configurator": ["website"],
    "/website/static": ["website"],
    # Auth
    "/oauth": ["auth_oauth"],
    "/auth_oauth": ["auth_oauth"],
    "/auth_ldap": ["auth_ldap"],
    "/auth_signup": ["auth_signup"],
    "/auth_totp": ["auth_totp"],
    "/auth_password_policy": ["auth_password_policy"],
    # Sign
    "/sign": ["sign"],
    "/sign/document": ["sign"],
    "/sign/template": ["sign"],
    "/sign/send": ["sign"],
    # Knowledge
    "/knowledge": ["knowledge"],
    "/knowledge/article": ["knowledge"],
    "/knowledge/tree": ["knowledge"],
    "/knowledge/share": ["knowledge"],
    # Spreadsheet
    "/spreadsheet": ["spreadsheet"],
    "/spreadsheet/dashboard": ["spreadsheet"],
    # Planning
    "/planning": ["planning"],
    "/planning/shift": ["planning"],
    "/planning/employee": ["planning"],
    # Timesheet
    "/timesheets": ["hr_timesheet"],
    "/my/timesheets": ["hr_timesheet", "portal"],
    # Expenses
    "/expenses": ["hr_expense"],
    "/my/expenses": ["hr_expense", "portal"],
    # Attendance
    "/attendances": ["hr_attendance"],
    "/hr_attendance": ["hr_attendance"],
    # Holidays
    "/leaves": ["hr_holidays"],
    "/my/leaves": ["hr_holidays", "portal"],
    # Recruitment
    "/recruitment": ["hr_recruitment"],
    "/recruitment/apply": ["hr_recruitment"],
    # Fleet
    "/fleet": ["fleet"],
    # Maintenance
    "/maintenance": ["maintenance"],
    "/my/maintenance": ["maintenance", "portal"],
    # Quality
    "/quality": ["quality"],
    # Manufacturing
    "/manufacturing": ["mrp"],
    "/mrp": ["mrp"],
    # Inventory / Stock
    "/inventory": ["stock"],
    "/my/inventory": ["stock", "portal"],
    # Purchase
    "/purchase": ["purchase"],
    "/my/purchase": ["purchase", "portal"],
    # Sale
    "/sale": ["sale"],
    "/my/sale": ["sale", "portal"],
    # Accounting
    "/accounting": ["account"],
    "/invoicing": ["account"],
    "/my/invoicing": ["account", "portal"],
    # Subscriptions
    "/subscriptions": ["sale_subscription"],
    # Rental
    "/rental": ["sale_rental"],
    # Repair
    "/repair": ["repair"],
    # Marketing
    "/marketing": ["marketing_card"],
    "/marketing_campaign": ["marketing_automation"],
    # Social
    "/social": ["social_media"],
    "/social/post": ["social_media"],
    "/social/feed": ["social_media"],
    # Email Marketing
    "/email_marketing": ["mass_mailing"],
    # SMS Marketing
    "/sms_marketing": ["mass_mailing_sms"],
    # Membership
    "/members": ["membership", "website_membership"],
    "/membership": ["membership"],
    # Lunch
    "/lunch": ["lunch"],
    # Groups (mail group)
    "/groups": ["mail_group"],
    # Gamification
    "/badges": ["gamification"],
    "/ranks": ["gamification"],
    # Newsletter
    "/newsletter": ["mass_mailing"],
    # Unsubscribe
    "/unsubscribe": ["mass_mailing"],
    # Rating
    "/rating": ["rating"],
    "/rating/feedback": ["rating"],
    # Link Tracker
    "/r": ["link_tracker"],
    "/link": ["link_tracker"],
    # Coupon
    "/coupon": ["coupon"],
    # Gift Card
    "/giftcard": ["gift_card"],
    # Loyalty
    "/loyalty": ["loyalty"],
    # Analytic
    "/analytics": ["analytic"],
    # Data Recycle
    "/data_recycle": ["data_recycle"],
    # Privacy Lookup
    "/privacy_lookup": ["privacy_lookup"],
    # Field Service
    "/field_service": ["field_service"],
    "/fsm": ["field_service"],
    # Studio
    "/studio": ["web_studio"],
    "/web/studio": ["web_studio"],
    # Base Import
    "/base_import": ["base_import"],
    # Partner Autocomplete
    "/partner_autocomplete": ["partner_autocomplete"],
    # CRM IAP Mine
    "/crm_iap_mine": ["crm_iap_mine"],
    # Google Services
    "/google_calendar": ["google_calendar"],
    "/google_gmail": ["google_gmail"],
    # Microsoft Services
    "/microsoft_calendar": ["microsoft_calendar"],
    "/microsoft_outlook": ["microsoft_outlook"],
    # UTM
    "/utm": ["utm"],
    # Board
    "/board": ["board"],
    # Digest
    "/digest": ["digest"],
    # Fetchmail
    "/fetchmail": ["fetchmail"],
    # IAP
    "/iap": ["iap"],
    # Barcodes
    "/barcodes": ["barcodes"],
    # Product Configurator
    "/product_configurator": ["sale_product_configurator", "website_sale_product_configurator"],
    # Web Map
    "/web_map": ["web_map"],
    # Web Gantt
    "/web_gantt": ["web_gantt"],
    # Web Grid
    "/web_grid": ["web_grid"],
    # Web Hierarchy
    "/web_hierarchy": ["web_hierarchy"],
    # Web PWA
    "/web_pwa": ["web_pwa"],
    # Web Tour
    "/web_tour": ["web_tour"],
    # Website Form
    "/website/form": ["website_form"],
    # Website Livechat
    "/website_livechat": ["website_livechat"],
    # Website Rating
    "/website_rating": ["website_rating"],
    # Website Sale Stock
    "/website_sale_stock": ["website_sale_stock"],
    # Website Sale Delivery
    "/website_sale_delivery": ["website_sale_delivery"],
    # Website Sale Loyalty
    "/website_sale_loyalty": ["website_sale_loyalty"],
    # Website Sale Picking
    "/website_sale_picking": ["website_sale_picking"],
    # Website Slides Forum
    "/website_slides_forum": ["website_slides_forum"],
    # Website Slides Survey
    "/website_slides_survey": ["website_slides_survey"],
    # Website CRM Score
    "/website_crm_score": ["website_crm_score"],
    # Website CRM Partner Assign
    "/website_crm_partner_assign": ["website_crm_partner_assign"],
    # HTTP Routing
    "/http_routing": ["http_routing"],
    # Base Geolocalize
    "/base_geolocalize": ["base_geolocalize"],
    # Base Address Extended
    "/base_address_extended": ["base_address_extended"],
    # Base VAT
    "/base_vat": ["base_vat"],
    # Base IBAN
    "/base_iban": ["base_iban"],
    # Attachment Indexation
    "/attachment_indexation": ["attachment_indexation"],
    # Base Automation
    "/base_automation": ["base_automation"],
    # Database Anonymization
    "/database_anonymization": ["database_anonymization"],
}

# Asset bundle name → module name(s)
# Odoo asset bundles often follow the pattern {module}.assets_{purpose}
BUNDLE_TO_MODULE = {
    "web.assets_frontend": ["web"],
    "web.assets_backend": ["web"],
    "web.assets_backend_lazy": ["web"],
    "web.assets_common": ["web"],
    "web.assets_common_lazy": ["web"],
    "web.assets_debug": ["web"],
    "web.assets_tests": ["web"],
    "web.assets_web": ["web"],
    "web.assets_wysiwyg": ["web_editor"],
    "web_editor.assets_wysiwyg": ["web_editor"],
    "web_editor.assets_media_dialog": ["web_editor"],
    "web_editor.wysiwyg_iframe_editor_assets": ["web_editor"],
    "website.assets_wysiwyg": ["website"],
    "website.assets_editor": ["website"],
    "website.assets_frontend": ["website"],
    "website.assets_frontend_minimal": ["website"],
    "website.assets_frontend_lazy": ["website"],
    "website_slides.slide_embed_assets": ["website_slides"],
    "website_slides.assets_slide_embed": ["website_slides"],
    "website_forum.assets_wysiwyg": ["website_forum"],
    "website_sale.assets": ["website_sale"],
    "website_sale.assets_frontend": ["website_sale"],
    "website_sale.assets_backend": ["website_sale"],
    "website_sale.assets_editor": ["website_sale"],
    "website_sale.assets_wysiwyg": ["website_sale"],
    "website_sale_stock.assets": ["website_sale_stock"],
    "website_sale_comparison.assets": ["website_sale_comparison"],
    "website_sale_wishlist.assets": ["website_sale_wishlist"],
    "website_sale_delivery.assets": ["website_sale_delivery"],
    "website_sale_loyalty.assets": ["website_sale_loyalty"],
    "website_sale_gift_card.assets": ["website_sale_gift_card"],
    "website_sale_picking.assets": ["website_sale_picking"],
    "website_sale_product_configurator.assets": ["website_sale_product_configurator"],
    "website_sale_slides.assets": ["website_sale_slides"],
    "website_event.assets": ["website_event"],
    "website_event.assets_frontend": ["website_event"],
    "website_event.assets_editor": ["website_event"],
    "website_event_track.assets": ["event_track"],
    "website_event_track_live.assets": ["event_track_live"],
    "website_event_meet.assets": ["event_meet"],
    "website_event_exhibitor.assets": ["event_exhibitor"],
    "website_event_sponsor.assets": ["event_sponsor"],
    "website_event_booth.assets": ["event_booth"],
    "website_blog.assets": ["website_blog"],
    "website_blog.assets_frontend": ["website_blog"],
    "website_blog.assets_editor": ["website_blog"],
    "website_profile.assets": ["website_profile"],
    "website_crm_partner_assign.assets": ["website_crm_partner_assign"],
    "website_crm.assets": ["website_crm"],
    "website_hr_recruitment.assets": ["website_hr_recruitment"],
    "website_appointment.assets": ["website_appointment"],
    "website_appointment.assets_frontend": ["website_appointment"],
    "website_calendar.assets": ["website_calendar"],
    "website_helpdesk.assets": ["website_helpdesk"],
    "website_helpdesk.assets_frontend": ["website_helpdesk"],
    "website_project.assets": ["website_project"],
    "website_membership.assets": ["website_membership"],
    "website_payment.assets": ["website_payment"],
    "website_mail.assets": ["website_mail"],
    "website_livechat.assets": ["website_livechat"],
    "website_rating.assets": ["website_rating"],
    "website_google_map.assets": ["website_google_map"],
    "website_form.assets": ["website_form"],
    "website_iframe_editor.assets": ["website"],
    "mail.assets_discuss_public": ["mail"],
    "mail.assets_messaging": ["mail"],
    "mail.assets_discuss": ["mail"],
    "mail.assets_backend": ["mail"],
    "im_livechat.assets_frontend": ["im_livechat"],
    "im_livechat.assets_core": ["im_livechat"],
    "im_livechat.assets_embed": ["im_livechat"],
    "point_of_sale.assets": ["point_of_sale"],
    "point_of_sale.assets_frontend": ["point_of_sale"],
    "point_of_sale.pos_assets_backend": ["point_of_sale"],
    "pos_restaurant.assets": ["pos_restaurant"],
    "survey.assets": ["survey"],
    "survey.survey_assets": ["survey"],
    "survey.survey_print_assets": ["survey"],
    "crm.assets": ["crm"],
    "sale.assets": ["sale"],
    "sale.assets_backend": ["sale"],
    "sale_subscription.assets": ["sale_subscription"],
    "sale_rental.assets": ["sale_rental"],
    "sale_timesheet.assets": ["sale_timesheet"],
    "sale_project.assets": ["sale_project"],
    "account.assets": ["account"],
    "account.assets_backend": ["account"],
    "account.assets_frontend": ["account"],
    "account_followup.assets": ["account_followup"],
    "account_payment.assets": ["account_payment"],
    "purchase.assets": ["purchase"],
    "stock.assets": ["stock"],
    "stock.assets_backend": ["stock"],
    "mrp.assets": ["mrp"],
    "mrp.assets_backend": ["mrp"],
    "mrp_workorder.assets": ["mrp"],
    "quality.assets": ["quality"],
    "maintenance.assets": ["maintenance"],
    "fleet.assets": ["fleet"],
    "hr.assets": ["hr"],
    "hr.assets_backend": ["hr"],
    "hr_attendance.assets": ["hr_attendance"],
    "hr_attendance.assets_backend": ["hr_attendance"],
    "hr_expense.assets": ["hr_expense"],
    "hr_expense.assets_backend": ["hr_expense"],
    "hr_holidays.assets": ["hr_holidays"],
    "hr_holidays.assets_backend": ["hr_holidays"],
    "hr_recruitment.assets": ["hr_recruitment"],
    "hr_recruitment.assets_backend": ["hr_recruitment"],
    "hr_contract.assets": ["hr_contract"],
    "hr_timesheet.assets": ["hr_timesheet"],
    "hr_timesheet.assets_backend": ["hr_timesheet"],
    "project.assets": ["project"],
    "project.assets_backend": ["project"],
    "project_timesheet_synchro.assets": ["project"],
    "event.assets": ["event"],
    "event.assets_backend": ["event"],
    "appointment.assets": ["appointment"],
    "appointment.assets_frontend": ["appointment"],
    "calendar.assets": ["calendar"],
    "calendar.assets_backend": ["calendar"],
    "helpdesk.assets": ["helpdesk"],
    "helpdesk.assets_backend": ["helpdesk"],
    "knowledge.assets": ["knowledge"],
    "knowledge.assets_backend": ["knowledge"],
    "sign.assets": ["sign"],
    "sign.assets_backend": ["sign"],
    "planning.assets": ["planning"],
    "planning.assets_backend": ["planning"],
    "spreadsheet.assets": ["spreadsheet"],
    "spreadsheet.assets_backend": ["spreadsheet"],
    "spreadsheet_dashboard.assets": ["spreadsheet_dashboard"],
    "gamification.assets": ["gamification"],
    "mass_mailing.assets": ["mass_mailing"],
    "mass_mailing.assets_backend": ["mass_mailing"],
    "mass_mailing.snippets_assets": ["mass_mailing"],
    "sms.assets": ["sms"],
    "snailmail.assets": ["snailmail"],
    "payment.assets": ["payment"],
    "payment.assets_backend": ["payment"],
    "loyalty.assets": ["loyalty"],
    "coupon.assets": ["coupon"],
    "gift_card.assets": ["gift_card"],
    "rating.assets": ["rating"],
    "link_tracker.assets": ["link_tracker"],
    "utm.assets": ["utm"],
    "digest.assets": ["digest"],
    "data_recycle.assets": ["data_recycle"],
    "privacy_lookup.assets": ["privacy_lookup"],
    "repair.assets": ["repair"],
    "delivery.assets": ["delivery"],
    "analytic.assets": ["analytic"],
    "barcodes.assets": ["barcodes"],
    "google_calendar.assets": ["google_calendar"],
    "google_gmail.assets": ["google_gmail"],
    "microsoft_calendar.assets": ["microsoft_calendar"],
    "microsoft_outlook.assets": ["microsoft_outlook"],
    "iap.assets": ["iap"],
    "fetchmail.assets": ["fetchmail"],
    "partner_autocomplete.assets": ["partner_autocomplete"],
    "phone_validation.assets": ["phone_validation"],
    "product.assets": ["product"],
    "resource.assets": ["resource"],
    "web_gantt.assets": ["web_gantt"],
    "web_grid.assets": ["web_grid"],
    "web_hierarchy.assets": ["web_hierarchy"],
    "web_kanban_gauge.assets": ["web_kanban_gauge"],
    "web_map.assets": ["web_map"],
    "web_pwa.assets": ["web_pwa"],
    "web_settings_dashboard.assets": ["web_settings_dashboard"],
    "web_tour.assets": ["web_tour"],
    "web_studio.assets": ["web_studio"],
    "web_unsplash.assets": ["web_unsplash"],
    "auth_oauth.assets": ["auth_oauth"],
    "auth_ldap.assets": ["auth_ldap"],
    "auth_signup.assets": ["auth_signup"],
    "auth_totp.assets": ["auth_totp"],
    "auth_password_policy.assets": ["auth_password_policy"],
    "base_import.assets": ["base_import"],
    "base_setup.assets": ["base_setup"],
    "base_automation.assets": ["base_automation"],
    "base_geolocalize.assets": ["base_geolocalize"],
    "base_address_extended.assets": ["base_address_extended"],
    "base_vat.assets": ["base_vat"],
    "base_iban.assets": ["base_iban"],
    "attachment_indexation.assets": ["attachment_indexation"],
    "portal.assets": ["portal"],
    "portal.assets_frontend": ["portal"],
    "bus.assets": ["bus"],
    "board.assets": ["board"],
    "contacts.assets": ["contacts"],
    "crm_iap_mine.assets": ["crm_iap_mine"],
    "marketing_automation.assets": ["marketing_automation"],
    "marketing_card.assets": ["marketing_card"],
    "social_media.assets": ["social_media"],
    "membership.assets": ["membership"],
    "lunch.assets": ["lunch"],
    "field_service.assets": ["field_service"],
    "database_anonymization.assets": ["database_anonymization"],
}


def match_css_classes(css_classes: list) -> list:
    """Given a list of CSS class names, return matching module names."""
    found = set()
    for cls in css_classes:
        cls_lower = cls.lower()
        for prefix, modules in CSS_CLASS_PREFIXES.items():
            prefix_lower = prefix.lower()
            if cls_lower.startswith(prefix_lower):
                found.update(modules)
    return sorted(found)


def match_model(model_name: str) -> list:
    """Given a model name, return matching module names."""
    return MODEL_TO_MODULE.get(model_name, [])


def match_route(route: str) -> list:
    """Given a URL path, return matching module names."""
    return ROUTE_TO_MODULE.get(route, [])


def match_bundle(bundle_name: str) -> list:
    """Given an asset bundle name, return matching module names."""
    return BUNDLE_TO_MODULE.get(bundle_name, [])
