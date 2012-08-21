#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

#include <mhash.h>

#define VMODACCESS_LOG(...) WSP(sp, SLT_VCL_Log, __VA_ARGS__);

#define DEBUG

#ifdef DEBUG
#define VMODACCESS_DEBUG(...) syslog(LOG_INFO, __VA_ARGS__);
#else
#define VMODACCESS_DEBUG(...) ;
#endif

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return (0);
}

unsigned
vmod_check(struct sess *sp, const char *service, const char *cookie_name, const char *salt)
{
        char *cookies_header, *cookies_header_dup;
        char **cookies_ptrptr;

        char *current_cookie, **cookie_ptrptr;
        char *current_cookie_name = NULL, *current_cookie_value = NULL, **current_cookie_value_ptrptr = NULL;

        char *version, *services, *services_dup, *user_id, *checksum;
        char checksum_input[8192], checksum_output[32];

        unsigned char *hash;
        MHASH mhash_struct;
        int i;

        char **services_ptrptr, **services_name_date_ptrptr;
        char *services_name, *services_date, *services_name_date;

        time_t service_date_timestamp;

        if (!service || !cookie_name || !salt)
        {
            VMODACCESS_LOG("invalid call to access.check()");
            return 0;
            // erreur 500
        }

        VMODACCESS_DEBUG("--- entering vmod_access");

        cookies_header = VRT_GetHdr(sp, HDR_REQ, "\07Cookie:");
        if (cookies_header != NULL)
        {
            // Got some covokies in request, try to find ours
            cookies_header_dup = (char *) strdup(cookies_header);
            VMODACCESS_DEBUG("cookies header = '%s'", cookies_header);

            cookies_ptrptr = (char**) malloc(sizeof(char*));
            for (current_cookie = strtok_r(cookies_header_dup, "; ", cookies_ptrptr);
                 current_cookie != NULL;
                 current_cookie = strtok_r(NULL, "; ", cookies_ptrptr))
            {
                 // Extract cookie name and value
            	cookie_ptrptr = (char**) malloc(sizeof(char*));
            	current_cookie_name = strtok_r(current_cookie, "=", cookie_ptrptr);
            	current_cookie_value = strtok_r(NULL, "=", cookie_ptrptr);

                if (strcmp(current_cookie_name, cookie_name) == 0)
                {
                    // Found our cookie, extract fields
                	VMODACCESS_DEBUG("got cookie '%s' = '%s', matches", current_cookie_name, current_cookie_value);

                    if (current_cookie_value != NULL)
                    {
                        current_cookie_value_ptrptr = (char**) malloc(sizeof(char*));
                        version	= strtok_r(current_cookie_value, "-", current_cookie_value_ptrptr);
                        if (!version)
                        {
                            VMODACCESS_DEBUG("can't extract version in '%s'!", current_cookie_value);
                            continue;
                        }

                        services = strtok_r(NULL, "-", current_cookie_value_ptrptr);
                        if (!services)
                        {
                            VMODACCESS_DEBUG("can't extract services in '%s'!", current_cookie_value);
                            continue;
                        }

                        user_id	= strtok_r(NULL, "-", current_cookie_value_ptrptr);
                        if (!user_id)
                        {
                            VMODACCESS_DEBUG("can't extract user_id in '%s'!", current_cookie_value);
                            continue;
                        }

                        checksum = strtok_r(NULL, "-", current_cookie_value_ptrptr);
                        if (!checksum)
                        {
                            VMODACCESS_DEBUG("can't extract checksum in '%s'!", current_cookie_value);
                            continue;
                        }

                        // Got all fields in cookie
                        VMODACCESS_DEBUG("found version '%s', services '%s', user_id '%s', checksum '%s'", version, services, user_id, checksum);

                        // Extract all (service, date)
                        services_ptrptr = (char**) malloc(sizeof(char*));
                        services_dup = strdup(services);
					    for (services_name_date = strtok_r(services_dup, "~", services_ptrptr);
							 services_name_date != NULL;
							 services_name_date = strtok_r(NULL, "~", services_ptrptr))
					    {
						    services_name_date_ptrptr = (char**) malloc(sizeof(char*));
						    services_name = strtok_r(services_name_date, ":", services_name_date_ptrptr);
						    services_date = strtok_r(NULL, ":", services_name_date_ptrptr);

                            // Search for a matching service name
                            VMODACCESS_DEBUG("name = '%s', date = '%s'", services_name, services_date);
                            if (!services_name || !services_date)
                            {
                                continue;
                            }
	
							// Compare substrings as service "foo" in cookie must match service "foo_YYYYMMDD" in access.check() 
                            if (strstr(service, services_name))
                            {
                                // Service name found, check date is still valid
                                VMODACCESS_DEBUG("cookie service name '%s' matches '%s'!", services_name, service);
                                errno=0;
                                service_date_timestamp = (time_t)strtol(services_date, NULL, 10);
                                if (errno != 0)
                                {
                                    VMODACCESS_DEBUG("invalid date '%s'", services_date);
                                    continue;
                                }

                                // Check that date is not in the past
                                if(service_date_timestamp >= time(NULL))
                                {
                                    // Found the right service name with a valid date, compare checksum
                                    sprintf(checksum_input, "%s%s%s%s", salt, version, services, user_id);
                                    VMODACCESS_DEBUG("valid date, compute checksum for '%s'", checksum_input);

                                    mhash_struct = mhash_init(MHASH_MD5);
                                    if (mhash_struct == MHASH_FAILED)
                                    {
                                        VMODACCESS_DEBUG("couldn't compute hash!", service);
                                        // erreur 503
                                    }
                                    mhash(mhash_struct, checksum_input, strlen(checksum_input));
                                    hash = mhash_end(mhash_struct);
                                    for (i = 0; i < mhash_get_block_size(MHASH_MD5); i++)
                                    {
                                        sprintf(checksum_output + i*2, "%02x", hash[i]);
                                    }

                                    // Checksum is valid, grant access!
                                    if (strcmp(checksum_output, checksum) == 0)
                                    {
                                        // log
                                        VMODACCESS_DEBUG("computed checksum '%s' matches cookie '%s', access granted!", checksum_output, checksum);
                                        return 1;
                                    }
                                    else
                                    {
                                        VMODACCESS_DEBUG("computed checksum '%s' doesn't match cookie '%s'", checksum_output, checksum);
                                    }
                                }
                                else
                                {
                                    VMODACCESS_DEBUG("date '%s' in past", services_date);
                                }
                            }
                        }
                    }
                }
            }
        }
        else
        {
            VMODACCESS_DEBUG("no cookies sent with request");
        }

        return 0;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
