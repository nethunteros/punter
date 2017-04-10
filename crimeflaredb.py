import zipfile
import urllib2
import os.path
import os

def dl_crimeflare():

    # http://stackoverflow.com/a/22776

    if os.path.exists('data/ipout'):
        print('[+] Detected IPOUT file in data.  Removing and redownloading')
        os.remove('data/ipout')

    try:
        url = 'http://crimeflare.net:82/domains/ipout.zip'
        file_name = url.split('/')[-1]
        u = urllib2.urlopen(url)
        f = open(file_name, 'wb')
        meta = u.info()
        file_size = int(meta.getheaders("Content-Length")[0])
        print "[+] Downloading: %s Bytes: %s" % (file_name, file_size)

        file_size_dl = 0
        block_sz = 8192
        while True:
            buffer = u.read(block_sz)
            if not buffer:
                break

            file_size_dl += len(buffer)
            f.write(buffer)
            status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
            status = status + chr(8)*(len(status)+1)
            print status,

        f.close()
        unzip_db(file_name)
        os.remove(file_name)
    except:
        print("[!] Error downloading crimeflaredb!")
        exit()

def unzip_db(ipout):

    print("[+] Unzpping %s " % ipout)
    zip_ref = zipfile.ZipFile(ipout, 'r')
    zip_ref.extractall('data')
    zip_ref.close()

