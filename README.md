# garminspo2
stores Garmin SpO2 and presents it for Apple Health and Intervals.icu

based on https://git.mbirth.uk/mbirth/garminspo2applehealth which uses his own Apple Shortcut. Grab that one.

You will want some basic `libapache2-mod-php` to serve the PHP publically and you point the shortcut at that.

Move the example to `auth.py` and the database to `spo2.db3`. Plop the PHP into your `/var/www/foo` and make sure it can read the sqlite.

This will also update last night's Garmin sleep SpO2 average to Intervals.ICU.
