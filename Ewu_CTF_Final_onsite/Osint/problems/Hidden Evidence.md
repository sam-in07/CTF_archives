The original image file has been recovered from the evidence drive. Although the image itself reveals little information, its metadata contains several valuable forensic artifacts

Flag Format : ROBOFEST{camera_model}

exiftool image_name.jpg | grep -i "Model"
exiftool Chall-1to41.jpg  | grep -i "Model" 

┌──(samin㉿kali)-[~/…/Saminsfiiles/CTF_archives/Ewu_CTF_Final_onsite/Osint]
└─$ file  Chall-1to41.jpg
Chall-1to41.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 679x900, components 3

"exiftool(-k).exe


