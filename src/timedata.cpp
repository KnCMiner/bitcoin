// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "timedata.h"

#include "netbase.h"
#include "sync.h"
#include "ui_interface.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/foreach.hpp>

using namespace std;

static CCriticalSection cs_nTimeOffset;
static int64_t nTimeOffset = 0;

/**
 * "Never go to sea with two chronometers; take one or three."
 * Our three time sources are:
 *  - System clock
 *  - Median of other nodes clocks
 *  - The user (asking the user to fix the system clock if the first two disagree)
 */
int64_t GetTimeOffset()
{
    LOCK(cs_nTimeOffset);
    return nTimeOffset;
}

int64_t GetAdjustedTime()
{
    return GetTime() + GetTimeOffset();
}

static int64_t abs64(int64_t n)
{
    return (n >= 0 ? n : -n);
}

void AddTimeData(const CNetAddr& ip, int64_t nOffsetSample)
{
    const int medianRange = 200;
    LOCK(cs_nTimeOffset);
    // Ignore duplicates
    static set<CNetAddr> setKnown;
    if (!setKnown.insert(ip).second)
        return;

    // Prune old addresses
    static list<CNetAddr> listKnown;
    listKnown.push_front(ip);
    while (listKnown.size() > medianRange) {
        CNetAddr oldest = listKnown.back();
        setKnown.erase(oldest);
        listKnown.pop_back();
    }

    // Add data
    static CMedianFilter<int64_t> vTimeOffsets(medianRange,0);
    vTimeOffsets.input(nOffsetSample);
    LogPrintf("Added time data, samples %d, offset %+d (%+d minutes)\n", vTimeOffsets.size(), nOffsetSample, nOffsetSample/60);

    if (vTimeOffsets.size() >= 5) {
        int64_t nMedian = vTimeOffsets.median();
        // Only let other nodes change our time by so much, and only if local clock no trusted
        if (abs64(nMedian) < 70 * 60 && !GetBoolArg("-trustlocalclock", false)) {
            // Preserve old "bug" of only adjusting network time on data from first 199 nodes
            // as this may explain why we've never seen attacks which manipulate the clock
            // offset. (see issue #4521).
            // Note: This limits network time adjustments to detect static clock offset
            // errors at startup, and do not compensate for runtime clock drift.
            if (vTimeOffsets.size() < medianRange)
                nTimeOffset = nMedian;
        } else {
            nTimeOffset = 0;
        }

        // If nobody has a time different than ours but within 5 minutes of ours, give a warning
        bool fMatch = false;
        std::vector<int64_t> vSorted = vTimeOffsets.sorted();
        BOOST_FOREACH(int64_t nOffset, vSorted)
            if (nOffset != 0 && abs64(nOffset) < 5 * 60)
                fMatch = true;

        // If median time too far off, give a warning
        if (abs64(nMedian) > 15 * 60)
            fMatch = false;

        if (!fMatch) {
            string strMessage = _("Warning: Please check that your computer's date and time are correct! If your clock is wrong Bitcoin Core will not work properly.");
            strMiscWarning = strMessage;
            LogPrintf("*** %s\n", strMessage);
            static bool fDone;
            if (!fDone) {
                fDone = true;
                uiInterface.ThreadSafeMessageBox(strMessage, "", CClientUIInterface::MSG_WARNING);
            }
        }
        if (fDebug) {
            BOOST_FOREACH(int64_t n, vSorted)
                LogPrintf("%+d  ", n);
            LogPrintf("|  ");
        }
        LogPrintf("nTimeOffset = %+d  (%+d minutes)\n", nTimeOffset, nTimeOffset/60);
    }
}
