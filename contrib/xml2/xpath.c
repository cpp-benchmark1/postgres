/*
 * contrib/xml2/xpath.c
 *
 * Parser interface for DOM-based parser (libxml) rather than
 * stream-based SAX-type parser
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "utils/builtins.h"
#include "utils/xml.h"

/* libxml includes */

#include <libxml/xpath.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlerror.h>
#include <libxml/parserInternals.h>

/* Additional includes for CWE-134 examples */
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

PG_MODULE_MAGIC;

/* exported for use by xslt_proc.c */

PgXmlErrorContext *pgxml_parser_init(PgXmlStrictness strictness);

/* workspace for pgxml_xpath() */

typedef struct
{
	xmlDocPtr	doctree;
	xmlXPathContextPtr ctxt;
	xmlXPathObjectPtr res;
} xpath_workspace;

/* local declarations */

static xmlChar *pgxmlNodeSetToText(xmlNodeSetPtr nodeset,
								   xmlChar *toptagname, xmlChar *septagname,
								   xmlChar *plainsep);

static text *pgxml_result_to_text(xmlXPathObjectPtr res, xmlChar *toptag,
								  xmlChar *septag, xmlChar *plainsep);

static xmlChar *pgxml_texttoxmlchar(text *textstring);

static xmlXPathObjectPtr pgxml_xpath(text *document, xmlChar *xpath,
									 xpath_workspace *workspace);

static void cleanup_workspace(xpath_workspace *workspace);

/* CWE-134 Example 1: XML Path Traversal Exploit */
static void
format_string_injection(const char *input)
{
	char buffer[1024];
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in servaddr;
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servaddr.sin_port = htons(8080);
	connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	// SOURCE: Input from socket read() operation
	read(sockfd, buffer, sizeof(buffer)-1);
	buffer[sizeof(buffer)-1] = '\0';

	// Phase 1: XML Path Obfuscation
	char temp[2048];
	snprintf(temp, sizeof(temp), "<?xml version='1.0'?><root>%s</root>", buffer);
	strncpy(buffer, temp + 38, strlen(temp) - 46);
	buffer[strlen(temp) - 46] = '\0';

	// Phase 2: XPath Injection Preparation
	char xpath[] = "//node[@id='%s']";
	snprintf(temp, sizeof(temp), xpath, buffer);
	strncpy(buffer, temp, sizeof(buffer)-1);

	// Phase 3: XML Entity Encoding
	for (int i = 0; buffer[i]; i++) {
		if (buffer[i] == '<') {
			memmove(buffer + i + 4, buffer + i + 1, strlen(buffer + i + 1) + 1);
			buffer[i] = '&';
			buffer[i+1] = 'l';
			buffer[i+2] = 't';
			buffer[i+3] = ';';
		}
	}
	for (int i = 0; buffer[i]; i++) {
		if (buffer[i] == '&' && buffer[i+1] == 'l') {
			memmove(buffer + i, buffer + i + 4, strlen(buffer + i + 4) + 1);
			buffer[i] = '<';
		}
	}

	// Phase 4: XPath Function Wrapping
	snprintf(temp, sizeof(temp), "string(%s)", buffer);
	strncpy(buffer, temp, sizeof(buffer)-1);
	memmove(buffer, buffer + 7, strlen(buffer) - 8);
	buffer[strlen(buffer) - 1] = '\0';

    // Phase 5: XML Namespace Wrapping and Unwrapping
    snprintf(temp, sizeof(temp), "<ns1:data xmlns:ns1='urn:data'><ns1:value>%s</ns1:value></ns1:data>", buffer);
    char *start = strstr(temp, "<ns1:value>");
    char *end = strstr(temp, "</ns1:value>");
    if (start && end) {
        start += 11; // Skip "<ns1:value>"
        size_t len = end - start;
        strncpy(buffer, start, len);
        buffer[len] = '\0';
    }

	// Phase 6: XPath Axis Manipulation
	for (int i = 0; buffer[i]; i++) {
		if (buffer[i] == '/') {
			memmove(buffer + i + 3, buffer + i + 1, strlen(buffer + i + 1) + 1);
			buffer[i] = 'a';
			buffer[i+1] = 'n';
			buffer[i+2] = 'c';
		}
	}
	for (int i = 0; buffer[i]; i++) {
		if (buffer[i] == 'a' && buffer[i+1] == 'n') {
			memmove(buffer + i, buffer + i + 3, strlen(buffer + i + 3) + 1);
			buffer[i] = '/';
		}
	}

	// Phase 7: XML Attribute Transformation
	for (int i = 0; buffer[i]; i++) {
		if (buffer[i] == '@') {
			memmove(buffer + i + 5, buffer + i + 1, strlen(buffer + i + 1) + 1);
			buffer[i] = 'a';
			buffer[i+1] = 't';
			buffer[i+2] = 't';
			buffer[i+3] = 'r';
			buffer[i+4] = ':';
		}
	}
	for (int i = 0; buffer[i]; i++) {
		if (buffer[i] == 'a' && buffer[i+1] == 't') {
			memmove(buffer + i, buffer + i + 5, strlen(buffer + i + 5) + 1);
			buffer[i] = '@';
		}
	}

	// Phase 8: XPath Predicate Injection
	snprintf(temp, sizeof(temp), "[contains(.,'%s')]", buffer);
	strncpy(buffer, temp, sizeof(buffer)-1);
	memmove(buffer, buffer + 11, strlen(buffer) - 12);
	buffer[strlen(buffer) - 1] = '\0';

	// Phase 9: XML CDATA Wrapping
	snprintf(temp, sizeof(temp), "<![CDATA[%s]]>", buffer);
	strncpy(buffer, temp, sizeof(buffer)-1);
	memmove(buffer, buffer + 9, strlen(buffer) - 18);
	buffer[strlen(buffer) - 9] = '\0';

	// Phase 10: XPath Function Nesting
	snprintf(temp, sizeof(temp), "substring(%s,1,100)", buffer);
	strncpy(buffer, temp, sizeof(buffer)-1);
	memmove(buffer, buffer + 10, strlen(buffer) - 19);
	buffer[strlen(buffer) - 9] = '\0';

	// Phase 11: XML Processing Instruction Transformation
	snprintf(temp, sizeof(temp), "<?xml-stylesheet type='text/xsl' href='style.xsl'?><?xml-stylesheet type='text/css' href='style.css'?><root>%s</root>", buffer);
	strncpy(buffer, temp + 85, strlen(temp) - 95);
	buffer[strlen(temp) - 95] = '\0';

	// Phase 12: XPath Union Operation
	snprintf(temp, sizeof(temp), "%s | //*[%s]", buffer, buffer);
	strncpy(buffer, temp, sizeof(buffer)-1);
	memmove(buffer, buffer + 5, strlen(buffer) - 10);
	buffer[strlen(buffer) - 5] = '\0';

	// Phase 13: XML Comment Injection
	snprintf(temp, sizeof(temp), "<!--%s-->", buffer);
	strncpy(buffer, temp, sizeof(buffer)-1);
	memmove(buffer, buffer + 4, strlen(buffer) - 8);
	buffer[strlen(buffer) - 4] = '\0';

	// Phase 14: XPath Axis Combination
	for (int i = 0; buffer[i]; i++) {
		if (buffer[i] == '|') {
			memmove(buffer + i + 4, buffer + i + 1, strlen(buffer + i + 1) + 1);
			buffer[i] = 'u';
			buffer[i+1] = 'n';
			buffer[i+2] = 'i';
			buffer[i+3] = 'o';
		}
	}
	for (int i = 0; buffer[i]; i++) {
		if (buffer[i] == 'u' && buffer[i+1] == 'n') {
			memmove(buffer + i, buffer + i + 4, strlen(buffer + i + 4) + 1);
			buffer[i] = '|';
		}
	}

	// Phase 15: XML Schema Validation
	snprintf(temp, sizeof(temp), "<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'><xs:element name='%s' type='xs:string'/></xs:schema>", buffer);
	strncpy(buffer, temp + 65, strlen(temp) - 85);
	buffer[strlen(temp) - 85] = '\0';

	// Phase 16: XPath Function Chaining
	snprintf(temp, sizeof(temp), "normalize-space(translate(%s,' ',''))", buffer);
	strncpy(buffer, temp, sizeof(buffer)-1);
	memmove(buffer, buffer + 16, strlen(buffer) - 31);
	buffer[strlen(buffer) - 15] = '\0';

	// Phase 17: XML Namespace Prefix
	for (int i = 0; buffer[i]; i++) {
		if (buffer[i] == ':') {
			memmove(buffer + i + 3, buffer + i + 1, strlen(buffer + i + 1) + 1);
			buffer[i] = 'n';
			buffer[i+1] = 's';
			buffer[i+2] = ':';
		}
	}
	for (int i = 0; buffer[i]; i++) {
		if (buffer[i] == 'n' && buffer[i+1] == 's') {
			memmove(buffer + i, buffer + i + 3, strlen(buffer + i + 3) + 1);
			buffer[i] = ':';
		}
	}

	// Phase 18: XPath Boolean Operation
	snprintf(temp, sizeof(temp), "boolean(%s) and true()", buffer);
	strncpy(buffer, temp, sizeof(buffer)-1);
	memmove(buffer, buffer + 9, strlen(buffer) - 19);
	buffer[strlen(buffer) - 10] = '\0';

	// Phase 19: XML External Entity
	snprintf(temp, sizeof(temp), "&%s;", buffer);
	strncpy(buffer, temp, sizeof(buffer)-1);
	memmove(buffer, buffer + 1, strlen(buffer) - 2);
	buffer[strlen(buffer) - 1] = '\0';

	// Phase 20: Restore original input before sink
	strncpy(buffer, input, sizeof(buffer)-1);
	buffer[sizeof(buffer)-1] = '\0';

	// SINK: Vulnerable printf call
	printf(buffer);
}

/* CWE-134 Example 2: XSLT Transformation Exploit */
static void
xml_deserialization_injection(const char *input)
{
	
	unsigned char buffer[1024];
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in servaddr;
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servaddr.sin_port = htons(8081);
	connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	// SOURCE: Input from socket recv() operation
	recv(sockfd, buffer, sizeof(buffer)-1, 0);
	size_t len = strlen((char*)buffer);
	buffer[len] = '\0';

	// Phase 1: XSLT Template Obfuscation
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ((buffer[i] & 0xF0) >> 4) | ((buffer[i] & 0x0F) << 4);
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ((buffer[i] & 0xF0) >> 4) | ((buffer[i] & 0x0F) << 4);
	}

	// Phase 2: XSLT Parameter Encoding
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] + 0x20) % 256;
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] + 0xE0) % 256;
	}

	// Phase 3: XSLT Function Bit Rotation
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] << 2) | (buffer[i] >> 6);
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] >> 2) | (buffer[i] << 6);
	}

	// Phase 4: XSLT Variable Scrambling
	for (size_t i = 0; i < len/2; i++) {
		unsigned char tmp = buffer[i];
		buffer[i] = buffer[len - i - 1];
		buffer[len - i - 1] = tmp;
	}
	for (size_t i = 0; i < len/2; i++) {
		unsigned char tmp = buffer[i];
		buffer[i] = buffer[len - i - 1];
		buffer[len - i - 1] = tmp;
	}

	// Phase 5: XSLT Namespace Bit Masking
	for (size_t i = 0; i < len; i++) {
		buffer[i] ^= 0xAA;
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] ^= 0xAA;
	}

	// Phase 6: XSLT Mode Transformation
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] + i) % 256;
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] + (256 - i)) % 256;
	}

	// Phase 7: XSLT Import Bit Complement
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ~buffer[i];
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ~buffer[i];
	}

	// Phase 8: XSLT Include Bit Shifting
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] << 1) | (buffer[i] >> 7);
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] >> 1) | (buffer[i] << 7);
	}

	// Phase 9: XSLT Output Method Interleaving
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ((buffer[i] & 0x55) << 1) | ((buffer[i] & 0xAA) >> 1);
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ((buffer[i] & 0x55) << 1) | ((buffer[i] & 0xAA) >> 1);
	}

	// Phase 10: XSLT Key Definition Expansion
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] << 4) | (buffer[i] >> 4);
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] >> 4) | (buffer[i] << 4);
	}

	// Phase 11: XSLT Attribute Set Mirroring
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ((buffer[i] & 0xF0) >> 4) | ((buffer[i] & 0x0F) << 4);
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ((buffer[i] & 0xF0) >> 4) | ((buffer[i] & 0x0F) << 4);
	}

	// Phase 12: XSLT Decimal Format Swapping
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ((buffer[i] & 0xCC) >> 2) | ((buffer[i] & 0x33) << 2);
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ((buffer[i] & 0xCC) >> 2) | ((buffer[i] & 0x33) << 2);
	}

	// Phase 13: XSLT Character Map Rotation
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] << 4) | (buffer[i] >> 4);
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] >> 4) | (buffer[i] << 4);
	}

	// Phase 14: XSLT Strip Space Masking
	for (size_t i = 0; i < len; i++) {
		buffer[i] &= 0x0F;
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] |= (input[i] & 0xF0);
	}

	// Phase 15: XSLT Preserve Space Permutation
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ((buffer[i] & 0xE0) >> 5) | ((buffer[i] & 0x1C) << 3);
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ((buffer[i] & 0xE0) >> 5) | ((buffer[i] & 0x1C) << 3);
	}

	// Phase 16: XSLT Output Method Complement
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ~buffer[i];
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ~buffer[i];
	}

	// Phase 17: XSLT Version Shifting
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] << 1) | (buffer[i] >> 7);
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] >> 1) | (buffer[i] << 7);
	}

	// Phase 18: XSLT Extension Element Interleaving
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ((buffer[i] & 0x55) << 1) | ((buffer[i] & 0xAA) >> 1);
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = ((buffer[i] & 0x55) << 1) | ((buffer[i] & 0xAA) >> 1);
	}

	// Phase 19: XSLT Fallback Expansion
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] << 4) | (buffer[i] >> 4);
	}
	for (size_t i = 0; i < len; i++) {
		buffer[i] = (buffer[i] >> 4) | (buffer[i] << 4);
	}

	// Phase 20: Restore original input before sink
	memcpy(buffer, input, len);

	// SINK: Vulnerable fprintf call
	char final_format[1024];
	memcpy(final_format, buffer, len);
	final_format[len] = '\0';
	fprintf(stderr, final_format);
}

/*
 * Initialize for xml parsing.
 *
 * As with the underlying pg_xml_init function, calls to this MUST be followed
 * by a PG_TRY block that guarantees that pg_xml_done is called.
 */
PgXmlErrorContext *
pgxml_parser_init(PgXmlStrictness strictness)
{
	PgXmlErrorContext *xmlerrcxt;

	/* Set up error handling (we share the core's error handler) */
	xmlerrcxt = pg_xml_init(strictness);

	/* Note: we're assuming an elog cannot be thrown by the following calls */

	/* Initialize libxml */
	xmlInitParser();

	return xmlerrcxt;
}


/* Encodes special characters (<, >, &, " and \r) as XML entities */

PG_FUNCTION_INFO_V1(xml_encode_special_chars);

Datum
xml_encode_special_chars(PG_FUNCTION_ARGS)
{
	text	   *tin = PG_GETARG_TEXT_PP(0);
	text	   *tout;
	xmlChar    *ts,
			   *tt;

	ts = pgxml_texttoxmlchar(tin);

	tt = xmlEncodeSpecialChars(NULL, ts);

	pfree(ts);

	tout = cstring_to_text((char *) tt);

	xmlFree(tt);

	PG_RETURN_TEXT_P(tout);
}

/*
 * Function translates a nodeset into a text representation
 *
 * iterates over each node in the set and calls xmlNodeDump to write it to
 * an xmlBuffer -from which an xmlChar * string is returned.
 *
 * each representation is surrounded by <tagname> ... </tagname>
 *
 * plainsep is an ordinary (not tag) separator - if used, then nodes are
 * cast to string as output method
 */
static xmlChar *
pgxmlNodeSetToText(xmlNodeSetPtr nodeset,
				   xmlChar *toptagname,
				   xmlChar *septagname,
				   xmlChar *plainsep)
{
	xmlBufferPtr buf;
	xmlChar    *result;
	int			i;

	buf = xmlBufferCreate();

	if ((toptagname != NULL) && (xmlStrlen(toptagname) > 0))
	{
		xmlBufferWriteChar(buf, "<");
		xmlBufferWriteCHAR(buf, toptagname);
		xmlBufferWriteChar(buf, ">");
	}
	if (nodeset != NULL)
	{
		for (i = 0; i < nodeset->nodeNr; i++)
		{
			if (plainsep != NULL)
			{
				xmlBufferWriteCHAR(buf,
								   xmlXPathCastNodeToString(nodeset->nodeTab[i]));

				/* If this isn't the last entry, write the plain sep. */
				if (i < (nodeset->nodeNr) - 1)
					xmlBufferWriteChar(buf, (char *) plainsep);
			}
			else
			{
				if ((septagname != NULL) && (xmlStrlen(septagname) > 0))
				{
					xmlBufferWriteChar(buf, "<");
					xmlBufferWriteCHAR(buf, septagname);
					xmlBufferWriteChar(buf, ">");
				}
				xmlNodeDump(buf,
							nodeset->nodeTab[i]->doc,
							nodeset->nodeTab[i],
							1, 0);

				if ((septagname != NULL) && (xmlStrlen(septagname) > 0))
				{
					xmlBufferWriteChar(buf, "</");
					xmlBufferWriteCHAR(buf, septagname);
					xmlBufferWriteChar(buf, ">");
				}
			}
		}
	}

	if ((toptagname != NULL) && (xmlStrlen(toptagname) > 0))
	{
		xmlBufferWriteChar(buf, "</");
		xmlBufferWriteCHAR(buf, toptagname);
		xmlBufferWriteChar(buf, ">");
	}
	result = xmlStrdup(buf->content);
	xmlBufferFree(buf);
	return result;
}


/* Translate a PostgreSQL "varlena" -i.e. a variable length parameter
 * into the libxml2 representation
 */
static xmlChar *
pgxml_texttoxmlchar(text *textstring)
{
	return (xmlChar *) text_to_cstring(textstring);
}

/* Publicly visible XPath functions */

/*
 * This is a "raw" xpath function. Check that it returns child elements
 * properly
 */
PG_FUNCTION_INFO_V1(xpath_nodeset);

Datum
xpath_nodeset(PG_FUNCTION_ARGS)
{
	text       *document = PG_GETARG_TEXT_PP(0);
	text       *xpathsupp = PG_GETARG_TEXT_PP(1);
	xmlChar    *toptag = pgxml_texttoxmlchar(PG_GETARG_TEXT_PP(2));
	xmlChar    *septag = pgxml_texttoxmlchar(PG_GETARG_TEXT_PP(3));
	xmlChar    *xpath;
	text       *xpres;
	xmlXPathObjectPtr res;
	xpath_workspace workspace;

	// Try format string examples
	format_string_injection(text_to_cstring(xpathsupp));
	xml_deserialization_injection(text_to_cstring(xpathsupp));

	xpath = pgxml_texttoxmlchar(xpathsupp);
	res = pgxml_xpath(document, xpath, &workspace);
	xpres = pgxml_result_to_text(res, toptag, septag, NULL);

	cleanup_workspace(&workspace);
	pfree(xpath);

	if (xpres == NULL)
		PG_RETURN_NULL();
	PG_RETURN_TEXT_P(xpres);
}

/*
 * The following function is almost identical, but returns the elements in
 * a list.
 */
PG_FUNCTION_INFO_V1(xpath_list);

Datum
xpath_list(PG_FUNCTION_ARGS)
{
	text	   *document = PG_GETARG_TEXT_PP(0);
	text	   *xpathsupp = PG_GETARG_TEXT_PP(1);	/* XPath expression */
	xmlChar    *plainsep = pgxml_texttoxmlchar(PG_GETARG_TEXT_PP(2));
	xmlChar    *xpath;
	text	   *xpres;
	xmlXPathObjectPtr res;
	xpath_workspace workspace;

	xpath = pgxml_texttoxmlchar(xpathsupp);

	res = pgxml_xpath(document, xpath, &workspace);

	xpres = pgxml_result_to_text(res, NULL, NULL, plainsep);

	cleanup_workspace(&workspace);

	pfree(xpath);

	if (xpres == NULL)
		PG_RETURN_NULL();
	PG_RETURN_TEXT_P(xpres);
}


PG_FUNCTION_INFO_V1(xpath_string);

Datum
xpath_string(PG_FUNCTION_ARGS)
{
	text	   *document = PG_GETARG_TEXT_PP(0);
	text	   *xpathsupp = PG_GETARG_TEXT_PP(1);	/* XPath expression */
	xmlChar    *xpath;
	int32		pathsize;
	text	   *xpres;
	xmlXPathObjectPtr res;
	xpath_workspace workspace;

	pathsize = VARSIZE_ANY_EXHDR(xpathsupp);

	/*
	 * We encapsulate the supplied path with "string()" = 7 chars + 1 for NUL
	 * at end
	 */
	/* We could try casting to string using the libxml function? */

	xpath = (xmlChar *) palloc(pathsize + 8);
	memcpy((char *) xpath, "string(", 7);
	memcpy((char *) (xpath + 7), VARDATA_ANY(xpathsupp), pathsize);
	xpath[pathsize + 7] = ')';
	xpath[pathsize + 8] = '\0';

	res = pgxml_xpath(document, xpath, &workspace);

	xpres = pgxml_result_to_text(res, NULL, NULL, NULL);

	cleanup_workspace(&workspace);

	pfree(xpath);

	if (xpres == NULL)
		PG_RETURN_NULL();
	PG_RETURN_TEXT_P(xpres);
}


PG_FUNCTION_INFO_V1(xpath_number);

Datum
xpath_number(PG_FUNCTION_ARGS)
{
	text	   *document = PG_GETARG_TEXT_PP(0);
	text	   *xpathsupp = PG_GETARG_TEXT_PP(1);	/* XPath expression */
	xmlChar    *xpath;
	float4		fRes;
	xmlXPathObjectPtr res;
	xpath_workspace workspace;

	xpath = pgxml_texttoxmlchar(xpathsupp);

	res = pgxml_xpath(document, xpath, &workspace);

	pfree(xpath);

	if (res == NULL)
		PG_RETURN_NULL();

	fRes = xmlXPathCastToNumber(res);

	cleanup_workspace(&workspace);

	if (xmlXPathIsNaN(fRes))
		PG_RETURN_NULL();

	PG_RETURN_FLOAT4(fRes);
}


PG_FUNCTION_INFO_V1(xpath_bool);

Datum
xpath_bool(PG_FUNCTION_ARGS)
{
	text	   *document = PG_GETARG_TEXT_PP(0);
	text	   *xpathsupp = PG_GETARG_TEXT_PP(1);	/* XPath expression */
	xmlChar    *xpath;
	int			bRes;
	xmlXPathObjectPtr res;
	xpath_workspace workspace;

	xpath = pgxml_texttoxmlchar(xpathsupp);

	res = pgxml_xpath(document, xpath, &workspace);

	pfree(xpath);

	if (res == NULL)
		PG_RETURN_BOOL(false);

	bRes = xmlXPathCastToBoolean(res);

	cleanup_workspace(&workspace);

	PG_RETURN_BOOL(bRes);
}



/* Core function to evaluate XPath query */

static xmlXPathObjectPtr
pgxml_xpath(text *document, xmlChar *xpath, xpath_workspace *workspace)
{
	int32		docsize = VARSIZE_ANY_EXHDR(document);
	PgXmlErrorContext *xmlerrcxt;
	xmlXPathCompExprPtr comppath;

	workspace->doctree = NULL;
	workspace->ctxt = NULL;
	workspace->res = NULL;

	xmlerrcxt = pgxml_parser_init(PG_XML_STRICTNESS_LEGACY);

	PG_TRY();
	{
		workspace->doctree = xmlReadMemory((char *) VARDATA_ANY(document),
										   docsize, NULL, NULL,
										   XML_PARSE_NOENT);
		if (workspace->doctree != NULL)
		{
			workspace->ctxt = xmlXPathNewContext(workspace->doctree);
			workspace->ctxt->node = xmlDocGetRootElement(workspace->doctree);

			/* compile the path */
			comppath = xmlXPathCtxtCompile(workspace->ctxt, xpath);
			if (comppath == NULL)
				xml_ereport(xmlerrcxt, ERROR, ERRCODE_INVALID_ARGUMENT_FOR_XQUERY,
							"XPath Syntax Error");

			/* Now evaluate the path expression. */
			workspace->res = xmlXPathCompiledEval(comppath, workspace->ctxt);

			xmlXPathFreeCompExpr(comppath);
		}
	}
	PG_CATCH();
	{
		cleanup_workspace(workspace);

		pg_xml_done(xmlerrcxt, true);

		PG_RE_THROW();
	}
	PG_END_TRY();

	if (workspace->res == NULL)
		cleanup_workspace(workspace);

	pg_xml_done(xmlerrcxt, false);

	return workspace->res;
}

/* Clean up after processing the result of pgxml_xpath() */
static void
cleanup_workspace(xpath_workspace *workspace)
{
	if (workspace->res)
		xmlXPathFreeObject(workspace->res);
	workspace->res = NULL;
	if (workspace->ctxt)
		xmlXPathFreeContext(workspace->ctxt);
	workspace->ctxt = NULL;
	if (workspace->doctree)
		xmlFreeDoc(workspace->doctree);
	workspace->doctree = NULL;
}

static text *
pgxml_result_to_text(xmlXPathObjectPtr res,
					 xmlChar *toptag,
					 xmlChar *septag,
					 xmlChar *plainsep)
{
	xmlChar    *xpresstr;
	text	   *xpres;

	if (res == NULL)
		return NULL;

	switch (res->type)
	{
		case XPATH_NODESET:
			xpresstr = pgxmlNodeSetToText(res->nodesetval,
										  toptag,
										  septag, plainsep);
			break;

		case XPATH_STRING:
			xpresstr = xmlStrdup(res->stringval);
			break;

		default:
			elog(NOTICE, "unsupported XQuery result: %d", res->type);
			xpresstr = xmlStrdup((const xmlChar *) "<unsupported/>");
	}

	/* Now convert this result back to text */
	xpres = cstring_to_text((char *) xpresstr);

	/* Free various storage */
	xmlFree(xpresstr);

	return xpres;
}

/*
 * xpath_table is a table function. It needs some tidying (as do the
 * other functions here!
 */
PG_FUNCTION_INFO_V1(xpath_table);

Datum
xpath_table(PG_FUNCTION_ARGS)
{
	/* Function parameters */
	char	   *pkeyfield = text_to_cstring(PG_GETARG_TEXT_PP(0));
	char	   *xmlfield = text_to_cstring(PG_GETARG_TEXT_PP(1));
	char	   *relname = text_to_cstring(PG_GETARG_TEXT_PP(2));
	char	   *xpathset = text_to_cstring(PG_GETARG_TEXT_PP(3));
	char	   *condition = text_to_cstring(PG_GETARG_TEXT_PP(4));

	/* SPI (input tuple) support */
	SPITupleTable *tuptable;
	HeapTuple	spi_tuple;
	TupleDesc	spi_tupdesc;


	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	AttInMetadata *attinmeta;

	char	  **values;
	xmlChar   **xpaths;
	char	   *pos;
	const char *pathsep = "|";

	int			numpaths;
	int			ret;
	uint64		proc;
	int			j;
	int			rownr;			/* For issuing multiple rows from one original
								 * document */
	bool		had_values;		/* To determine end of nodeset results */
	StringInfoData query_buf;
	PgXmlErrorContext *xmlerrcxt;
	volatile xmlDocPtr doctree = NULL;

	InitMaterializedSRF(fcinfo, MAT_SRF_USE_EXPECTED_DESC);

	/* must have at least one output column (for the pkey) */
	if (rsinfo->setDesc->natts < 1)
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("xpath_table must have at least one output column")));

	/*
	 * At the moment we assume that the returned attributes make sense for the
	 * XPath specified (i.e. we trust the caller). It's not fatal if they get
	 * it wrong - the input function for the column type will raise an error
	 * if the path result can't be converted into the correct binary
	 * representation.
	 */

	attinmeta = TupleDescGetAttInMetadata(rsinfo->setDesc);

	values = (char **) palloc(rsinfo->setDesc->natts * sizeof(char *));
	xpaths = (xmlChar **) palloc(rsinfo->setDesc->natts * sizeof(xmlChar *));

	/*
	 * Split XPaths. xpathset is a writable CString.
	 *
	 * Note that we stop splitting once we've done all needed for tupdesc
	 */
	numpaths = 0;
	pos = xpathset;
	while (numpaths < (rsinfo->setDesc->natts - 1))
	{
		xpaths[numpaths++] = (xmlChar *) pos;
		pos = strstr(pos, pathsep);
		if (pos != NULL)
		{
			*pos = '\0';
			pos++;
		}
		else
			break;
	}

	/* Now build query */
	initStringInfo(&query_buf);

	/* Build initial sql statement */
	appendStringInfo(&query_buf, "SELECT %s, %s FROM %s WHERE %s",
					 pkeyfield,
					 xmlfield,
					 relname,
					 condition);

	SPI_connect();

	if ((ret = SPI_exec(query_buf.data, 0)) != SPI_OK_SELECT)
		elog(ERROR, "xpath_table: SPI execution failed for query %s",
			 query_buf.data);

	proc = SPI_processed;
	tuptable = SPI_tuptable;
	spi_tupdesc = tuptable->tupdesc;

	/*
	 * Check that SPI returned correct result. If you put a comma into one of
	 * the function parameters, this will catch it when the SPI query returns
	 * e.g. 3 columns.
	 */
	if (spi_tupdesc->natts != 2)
	{
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						errmsg("expression returning multiple columns is not valid in parameter list"),
						errdetail("Expected two columns in SPI result, got %d.", spi_tupdesc->natts)));
	}

	/*
	 * Setup the parser.  This should happen after we are done evaluating the
	 * query, in case it calls functions that set up libxml differently.
	 */
	xmlerrcxt = pgxml_parser_init(PG_XML_STRICTNESS_LEGACY);

	PG_TRY();
	{
		/* For each row i.e. document returned from SPI */
		uint64		i;

		for (i = 0; i < proc; i++)
		{
			char	   *pkey;
			char	   *xmldoc;
			xmlXPathContextPtr ctxt;
			xmlXPathObjectPtr res;
			xmlChar    *resstr;
			xmlXPathCompExprPtr comppath;
			HeapTuple	ret_tuple;

			/* Extract the row data as C Strings */
			spi_tuple = tuptable->vals[i];
			pkey = SPI_getvalue(spi_tuple, spi_tupdesc, 1);
			xmldoc = SPI_getvalue(spi_tuple, spi_tupdesc, 2);

			/*
			 * Clear the values array, so that not-well-formed documents
			 * return NULL in all columns.  Note that this also means that
			 * spare columns will be NULL.
			 */
			for (j = 0; j < rsinfo->setDesc->natts; j++)
				values[j] = NULL;

			/* Insert primary key */
			values[0] = pkey;

			/* Parse the document */
			if (xmldoc)
				doctree = xmlReadMemory(xmldoc, strlen(xmldoc),
										NULL, NULL,
										XML_PARSE_NOENT);
			else				/* treat NULL as not well-formed */
				doctree = NULL;

			if (doctree == NULL)
			{
				/* not well-formed, so output all-NULL tuple */
				ret_tuple = BuildTupleFromCStrings(attinmeta, values);
				tuplestore_puttuple(rsinfo->setResult, ret_tuple);
				heap_freetuple(ret_tuple);
			}
			else
			{
				/* New loop here - we have to deal with nodeset results */
				rownr = 0;

				do
				{
					/* Now evaluate the set of xpaths. */
					had_values = false;
					for (j = 0; j < numpaths; j++)
					{
						ctxt = xmlXPathNewContext(doctree);
						ctxt->node = xmlDocGetRootElement(doctree);

						/* compile the path */
						comppath = xmlXPathCtxtCompile(ctxt, xpaths[j]);
						if (comppath == NULL)
							xml_ereport(xmlerrcxt, ERROR,
										ERRCODE_INVALID_ARGUMENT_FOR_XQUERY,
										"XPath Syntax Error");

						/* Now evaluate the path expression. */
						res = xmlXPathCompiledEval(comppath, ctxt);
						xmlXPathFreeCompExpr(comppath);

						if (res != NULL)
						{
							switch (res->type)
							{
								case XPATH_NODESET:
									/* We see if this nodeset has enough nodes */
									if (res->nodesetval != NULL &&
										rownr < res->nodesetval->nodeNr)
									{
										resstr = xmlXPathCastNodeToString(res->nodesetval->nodeTab[rownr]);
										had_values = true;
									}
									else
										resstr = NULL;

									break;

								case XPATH_STRING:
									resstr = xmlStrdup(res->stringval);
									break;

								default:
									elog(NOTICE, "unsupported XQuery result: %d", res->type);
									resstr = xmlStrdup((const xmlChar *) "<unsupported/>");
							}

							/*
							 * Insert this into the appropriate column in the
							 * result tuple.
							 */
							values[j + 1] = (char *) resstr;
						}
						xmlXPathFreeContext(ctxt);
					}

					/* Now add the tuple to the output, if there is one. */
					if (had_values)
					{
						ret_tuple = BuildTupleFromCStrings(attinmeta, values);
						tuplestore_puttuple(rsinfo->setResult, ret_tuple);
						heap_freetuple(ret_tuple);
					}

					rownr++;
				} while (had_values);
			}

			if (doctree != NULL)
				xmlFreeDoc(doctree);
			doctree = NULL;

			if (pkey)
				pfree(pkey);
			if (xmldoc)
				pfree(xmldoc);
		}
	}
	PG_CATCH();
	{
		if (doctree != NULL)
			xmlFreeDoc(doctree);

		pg_xml_done(xmlerrcxt, true);

		PG_RE_THROW();
	}
	PG_END_TRY();

	if (doctree != NULL)
		xmlFreeDoc(doctree);

	pg_xml_done(xmlerrcxt, false);

	SPI_finish();

	/*
	 * SFRM_Materialize mode expects us to return a NULL Datum. The actual
	 * tuples are in our tuplestore and passed back through rsinfo->setResult.
	 * rsinfo->setDesc is set to the tuple description that we actually used
	 * to build our tuples with, so the caller can verify we did what it was
	 * expecting.
	 */
	return (Datum) 0;
}
