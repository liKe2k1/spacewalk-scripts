#!/usr/bin/python
import re
import urllib2
import os
import errno
import traceback
import sys
import xml.etree.cElementTree as XML
import parseDebian


def main():

    security_msg = "test/"
    errata_file = 'debian-errata.xml'
    parsed_dir = security_msg + 'parsed/'

    try:
        os.stat(parsed_dir)
    except OSError:
        os.mkdir(parsed_dir)

    # remove errata_file from previous run
    try:
        os.remove(security_msg + errata_file)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise

    try:
        files = filter(lambda f: re.match('^\d{4}-msg\d{5}\.html', f), os.listdir(security_msg))
        parsed_files = filter(lambda f: re.match('^\d{4}-msg\d{5}\.html', f), os.listdir(parsed_dir))

        files_to_parse = list(set(files) - set(parsed_files))
        announcements = list()

        if not files_to_parse:
            print("No security announcements to parse today. Bye.")
            sys.exit(0)

        if len(files_to_parse) != len(files):
            print("Ignoring %d old security announcements already parsed." % (len(files) - len(files_to_parse)))

        for idx, f in enumerate(files_to_parse, start=1):
            print("Processing patch %d/%d (file: %s)" % (idx, len(files_to_parse), f))
            message_parser = parseDebian.MessageFile(os.path.join(security_msg, f))
            errata = message_parser.parse()
            if errata:
                announcements.append(errata)
                # move the file to our parsed files dir
                #os.rename(security_msg + f, parsed_dir + f)

        # if there are no advisories, just quit
        if not announcements:
            print("No security announcements available or parseable. Bye.")
            sys.exit(0)

        # write the advisory XML
        opt = XML.Element('patches')
        for advisory in announcements:
            adv = XML.SubElement(opt, advisory.getAdvisoryName())
            adv.set('description', advisory.errataDesc.strip())
            adv.set('issue_date', advisory.errataDate)
            adv.set('errataFrom', advisory.errataFrom)
            # prepend advisory name to synopsis. This makes it easier to search for the errata in Spacewalk WebUI
            adv.set('synopsis', advisory.getAdvisoryName() + ' ' + advisory.errataSynopsis)
            adv.set('release', advisory.errataRelease)
            adv.set('product', 'Debian Linux')
            adv.set('topic', 'N/A')
            adv.set('solution', 'N/A')
            adv.set('notes', 'N/A')
            if advisory.errataReboot != "":
                adv.set('keywords', advisory.errataReboot)
            adv.set('type', advisory.errataType)
            # adv.set('references', advisory.errataReferences.strip())

            # for every distribution (jessie, stretch, ...)
            # add the packages
            for dist in advisory.packages:
                d = XML.SubElement(adv, 'dist')
                d.set('name', dist)
                for package in advisory.packages[dist]:
                    pkg = XML.SubElement(d, 'package')
                    pkg.text = package

            # add CVEs
            for cve in advisory.cves:
                c = XML.SubElement(adv, 'cve')
                c.text = cve

        xml = XML.ElementTree(opt)
        xml.write(security_msg + errata_file)

    except Exception as e:
        print("Failed to parse messages due to exception %s" % e)
        traceback.print_exc(file=sys.stdout)
        sys.exit(2)


if __name__ == "__main__":
    main()