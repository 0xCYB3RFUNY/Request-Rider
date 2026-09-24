from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("lab", "0005_appsettings_response_size")]

    operations = [migrations.DeleteModel(name="AppSettings")]
