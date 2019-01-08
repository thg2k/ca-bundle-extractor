#!/usr/bin/php
<?php
/**
 * ca-bundle-extractor.php - Trusted CA bundle generator for eSignatures
 *
 * Description:
 *  - Generates a PEM bundle of the CAs authorized to generate qualified eSignatures
 *
 * Authors:
 *  - Giovanni Giacobbi <giovanni@giacobbi.net>
 *
 * Official repository:
 *  - https://github.com/thg2k/ca-bundle-extractor
 *
 * Version 1.0 - 9th/jan/2019
 *  - First published version
 *
 *
 * MIT License
 *
 * Copyright (c) 2019  Giovanni Giacobbi <giovanni@giacobbi.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

/* ----------------------------- DEFINITIONS ------------------------------ */

$CountryUrls = array(
  'IT' => "https://eidas.agid.gov.it/TL/TSL-IT.xml");

$ServiceType = array(
  'CA/QC'      => 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
  'IdV'        => 'http://uri.etsi.org/TrstSvc/Svctype/IdV',
  'TSA'        => 'http://uri.etsi.org/TrstSvc/Svctype/TSA',
  'TSA/QTST'   => 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST',
  'TSA/TSS-QC' => 'http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC');

$ServiceStatus = array(
  'deprecated' => 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel',
  'granted'    => 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
  'recognised' => 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel',
  'withdrawn'  => 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn');

$ServiceExtension = array(
  'eSeals'                => 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals',
  'eSignatures'           => 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures',
  'WebSiteAuthentication' => 'http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication');

/* list of conditions (exclusive) to meet for exporting the certificate */
$FilterBundle = array(
  array('Type'      => 'CA/QC',
        'Status'    => 'granted',
        'Extension' => 'eSignatures'));

/* ------------------------------ UTILITIES ------------------------------- */

function dbg($message = "") {
  /* uncomment to enable debug output */
  // fputs(STDERR, $message . "\n");
}

function output($message = "") {
  fprintf(STDERR, "%s\n", $message);
}

function error($message) {
  fprintf(STDERR, "Error: %s\n\n", $message);
  exit(1);
}

/* --------------------------------- MAIN --------------------------------- */

$infile = (isset($argv[1]) ? $argv[1] : null);
$outfile = (isset($argv[2]) ? $argv[2] : null);

if ($infile == "") {
  fprintf(STDERR, "Usage: %s <tsl-xml-file|@fetch:XX> [output-certs-file]\n\n", $argv[0]);
  fprintf(STDERR, "Examples:\n");
  fprintf(STDERR, "    %s TSL-IT.xml bundle.crt         (parse local file, save to local file)\n", $argv[0]);
  fprintf(STDERR, "    %s TSL-IT.xml > bundle.crt       (parse local file, redirected stdout)\n", $argv[0]);
  fprintf(STDERR, "    %s @fetch:IT bundle.crt          (download remote file, save to local file)\n", $argv[0]);
  fprintf(STDERR, "\n");
  exit(1);
}

/* parse xml data */
if (preg_match('/^@fetch:([a-z]{2})$/i', $infile, $regp)) {
  if (!isset($CountryUrls[strtoupper($regp[1])]))
    error("Unknown country \"" . $regp[1] . "\" for remote fetch");

  $url = $CountryUrls[strtoupper($regp[1])];

  output("[+] Downloading remote file from: " . $url);
  $data = file_get_contents($url);

  output("[+] Parsing downloaded data");
  $xml = @simplexml_load_string($data);
  unset($data);
}
else {
  output("[+] Parsing local XML file: " . $infile);
  $xml = @simplexml_load_file($infile);
}
if ($xml === false)
  error("Failed to parse XML data");

/* open the output file */
if ($outfile == "")
  $outfile = "php://stdout";
$fd = fopen($outfile, "w");

$stats_out = 0;
$stats_discarded = 0;

foreach ($xml->TrustServiceProviderList->TrustServiceProvider as $provider) {
  $provider_name = (string) $provider->TSPInformation->TSPName->Name[0];
  dbg("PROVIDER \"" . $provider_name . "\"");

  foreach ($provider->TSPServices->TSPService as $srv) {
    $xml_svc_info = $srv->ServiceInformation;
    $label_type = array_search((string) $xml_svc_info->ServiceTypeIdentifier, $ServiceType);
    $label_status = array_search((string) $xml_svc_info->ServiceStatus, $ServiceStatus);

    dbg(".. .. SERVICE status=$label_status type=$label_type");

    $label_exts = array();
    if ($xml_svc_info->ServiceInformationExtensions) {
      foreach ($xml_svc_info->ServiceInformationExtensions->Extension as $srv_ext) {
        if ($srv_ext->AdditionalServiceInformation) {
          $label_ext = array_search((string) $srv_ext->AdditionalServiceInformation->URI, $ServiceExtension);
          $label_exts[] = $label_ext;
          dbg(".. .. .. EXT for=$label_ext");
        }
      }
    }

    $x509_cert = (string) $xml_svc_info->ServiceDigitalIdentity->DigitalId->X509Certificate;

    $filter_match = false;
    foreach ($FilterBundle as $filter) {
      if ((!isset($filter['Type']) || ($filter['Type'] === $label_type)) &&
          (!isset($filter['Status']) || ($filter['Status'] === $label_status)) &&
          (!isset($filter['Extension']) || in_array($filter['Extension'], $label_exts, true)))
        $filter_match = true;
    }

    if ($filter_match) {
      $x509_cert_pem = "-----BEGIN CERTIFICATE-----\n" .
                       chunk_split($x509_cert, 64, "\n") .
                       "-----END CERTIFICATE-----\n";
      $x = openssl_x509_parse($x509_cert_pem);
      dbg(".. .. .. EXPORTING TRUSTED CERT: " . $x['name']);
      fputs($fd, $x509_cert_pem);
      $stats_out++;
    }
    else {
      dbg(".. .. .. DISCARDING (FILTERED)");
      $stats_discarded++;
    }
  }
}
fclose($fd);
unset($xml);

output("[+] Exported " . $stats_out . " certificate(s), " . $stats_discarded . " discarded");
output();
