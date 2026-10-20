package com.securityanalyst.gateway.identity;

import java.util.List;

/**
 * What "normal" looks like for one employee. The agent compares an incident against this
 * (an unusual country, a login at 3 a.m., an unknown device or caller).
 * Stored encrypted; see BaselineCipher.
 *
 * @param usualCountries  ISO country codes the person normally logs in from, e.g. "IN"
 * @param workdayStartUtc hour (0-23, UTC) the person usually starts work
 * @param workdayEndUtc   hour (0-23, UTC) the person usually stops work
 * @param knownDevices    device / browser descriptions seen before
 * @param knownContacts   email addresses the person normally deals with
 * @param knownNumbers    phone numbers the person normally deals with
 * @param homeCity        where the person is based, for "impossible travel" checks
 */
public record Baseline(
        List<String> usualCountries,
        int workdayStartUtc,
        int workdayEndUtc,
        List<String> knownDevices,
        List<String> knownContacts,
        List<String> knownNumbers,
        String homeCity) {
}
