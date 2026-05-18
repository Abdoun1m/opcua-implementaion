#include "whitelist.h"

const GatewayPoint GATEWAY_POINTS[] = {
    /* =========================================================
     * MES HEALTH
     * ========================================================= */
    { "MES.Health.Heartbeat",              1601, GW_TYPE_INT32 },
    { "MES.Health.Watchdog",               1602, GW_TYPE_INT32 },
    { "MES.Health.LastUpdateEpoch",        1604, GW_TYPE_INT32 },
    { "MES.Health.DataStale",              1605, GW_TYPE_BOOL },

    /* =========================================================
     * FACTORY - RAW / PROCESS
     * ========================================================= */
    { "Factory.EtatUsine",                 1112, GW_TYPE_BOOL },
    { "Factory.EtatInstallation",          1113, GW_TYPE_BOOL },

    { "Factory.Cuve1.NiveauBas",           1126, GW_TYPE_BOOL },
    { "Factory.Cuve1.NiveauHaut",          1127, GW_TYPE_BOOL },
    { "Factory.Cuve2.NiveauBas",           1128, GW_TYPE_BOOL },
    { "Factory.Cuve2.NiveauHaut",          1129, GW_TYPE_BOOL },
    { "Factory.Cuve3.NiveauBas",           1131, GW_TYPE_BOOL },
    { "Factory.Cuve3.NiveauHaut",          1132, GW_TYPE_BOOL },
    { "Factory.Cuve4.NiveauBas",           1133, GW_TYPE_BOOL },
    { "Factory.Cuve4.NiveauHaut",          1134, GW_TYPE_BOOL },
    { "Factory.Cuve5.NiveauBas",           1135, GW_TYPE_BOOL },
    { "Factory.Cuve5.NiveauHaut",          1136, GW_TYPE_BOOL },

    { "Factory.CycleActif",                1155, GW_TYPE_BOOL },
    { "Factory.RecyclageActif",            1156, GW_TYPE_BOOL },
    { "Factory.CycleTermine",              1157, GW_TYPE_BOOL },

    /* =========================================================
     * FACTORY MES - BOOLEAN SHADOWS
     * ========================================================= */
    { "Factory.MES.CycleActive",           1611, GW_TYPE_BOOL },
    { "Factory.MES.CycleDone",             1612, GW_TYPE_BOOL },
    { "Factory.MES.FactoryRunning",        1613, GW_TYPE_BOOL },
    { "Factory.MES.RecycleActive",         1614, GW_TYPE_BOOL },
    { "Factory.MES.Tank4HighShadow",       1615, GW_TYPE_BOOL },
    { "Factory.MES.Tank4LowShadow",        1616, GW_TYPE_BOOL },
    { "Factory.MES.Tank5HighShadow",       1617, GW_TYPE_BOOL },
    { "Factory.MES.Tank5LowShadow",        1618, GW_TYPE_BOOL },

    /* =========================================================
     * FACTORY MES - NUMERIC COUNTERS
     * ========================================================= */
    { "Factory.MES.Heartbeat",             1650, GW_TYPE_INT32 },
    { "Factory.MES.ProgramVersion",        1651, GW_TYPE_INT32 },
    { "Factory.MES.DefautCode",            1652, GW_TYPE_INT32 },
    { "Factory.MES.StateWord",             1653, GW_TYPE_INT32 },
    { "Factory.MES.CycleCount",            1654, GW_TYPE_INT32 },
    { "Factory.MES.RunTimeSeconds",        1655, GW_TYPE_INT32 },
    { "Factory.MES.GoodCount",             1656, GW_TYPE_INT32 },

    /* =========================================================
     * POWERGRID PLC1 - FIELD MIRROR
     * ========================================================= */
    { "PowerGrid.PLC1.PE.Etat",            1422, GW_TYPE_BOOL },
    { "PowerGrid.PLC1.FS.Etat",            1424, GW_TYPE_BOOL },
    { "PowerGrid.PLC1.GS.Etat",            1426, GW_TYPE_BOOL },
    { "PowerGrid.PLC1.Factory.Etat",       1428, GW_TYPE_BOOL },
    { "PowerGrid.PLC1.Homes.Etat",         1430, GW_TYPE_BOOL },
    { "PowerGrid.PLC1.Railway.Etat",       1432, GW_TYPE_BOOL },

    /* =========================================================
     * POWERGRID PLC2 - SOURCES / DISTRIBUTION
     * ========================================================= */
    { "PowerGrid.PLC2.PE.Etat",            1463, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.FS.Etat",            1467, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.GS.Etat",            1471, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.Factory.Etat",       1475, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.Homes.Etat",         1478, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.Railway.Etat",       1481, GW_TYPE_BOOL },

    { "PowerGrid.PLC2.PE.Production",      1464, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.FS.Production",      1468, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.GS.Production",      1472, GW_TYPE_BOOL },

    { "PowerGrid.PLC2.Factory.Distribue",  1476, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.Homes.Distribue",    1479, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.Railway.Distribue",  1482, GW_TYPE_BOOL },

    { "PowerGrid.PLC2.PE.Power",           1465, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.FS.Power",           1469, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.GS.Power",           1473, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.TAP",                1494, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.TCP",                1495, GW_TYPE_DOUBLE },

    /* =========================================================
     * POWERGRID PLC2 MES - EXISTING
     * ========================================================= */
    { "PowerGrid.PLC2.MES.FactoryServed",  1641, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.MES.HomesServed",    1642, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.MES.RailwayServed",  1643, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.MES.DeficitActive",  1644, GW_TYPE_BOOL },
    { "PowerGrid.PLC2.MES.Losses",         1645, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.MES.ReserveMargin",  1646, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.MES.FactoryDemand",  1647, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.MES.HomesDemand",    1648, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.MES.RailwayDemand",  1649, GW_TYPE_DOUBLE },

    /* =========================================================
     * POWERGRID PLC2 MES - EXTRA VALUES
     * ========================================================= */
    { "PowerGrid.PLC2.MES.PEPowerValue",       1670, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.MES.FSPowerValue",       1671, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.MES.GSPowerValue",       1672, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.MES.TotalProduction",    1673, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.MES.TotalConsumption",   1674, GW_TYPE_DOUBLE },
    { "PowerGrid.PLC2.MES.ReserveValue",       1675, GW_TYPE_DOUBLE },

    /* =========================================================
     * RAIL AUTO
     * ========================================================= */
    { "RailAuto.Etape1.Activation",        1321, GW_TYPE_BOOL },
    { "RailAuto.Etape1.DelaiOuverture",    1322, GW_TYPE_BOOL },
    { "RailAuto.Etape1.DelaiFermeture",    1323, GW_TYPE_BOOL },
    { "RailAuto.Etape1.Terminee",          1324, GW_TYPE_BOOL },

    { "RailAuto.Etape2.Activation",        1331, GW_TYPE_BOOL },
    { "RailAuto.Etape2.DelaiOuverture",    1332, GW_TYPE_BOOL },
    { "RailAuto.Etape2.DelaiFermeture",    1333, GW_TYPE_BOOL },
    { "RailAuto.Etape2.Terminee",          1334, GW_TYPE_BOOL },

    { "RailAuto.Etape3.Activation",        1341, GW_TYPE_BOOL },
    { "RailAuto.Etape3.DelaiOuverture",    1342, GW_TYPE_BOOL },
    { "RailAuto.Etape3.DelaiFermeture",    1343, GW_TYPE_BOOL },
    { "RailAuto.Etape3.Terminee",          1344, GW_TYPE_BOOL },

    { "RailAuto.Etape4.Activation",        1351, GW_TYPE_BOOL },
    { "RailAuto.Etape4.DelaiOuverture",    1352, GW_TYPE_BOOL },
    { "RailAuto.Etape4.DelaiFermeture",    1353, GW_TYPE_BOOL },
    { "RailAuto.Etape4.Terminee",          1354, GW_TYPE_BOOL },

    /* =========================================================
     * RAIL MANUAL MES - BOOLEAN SHADOWS + EXISTING COUNTERS
     * ========================================================= */
    { "RailManual.MES.FESRouteValid",       1621, GW_TYPE_BOOL },
    { "RailManual.MES.MarrakechRouteValid", 1622, GW_TYPE_BOOL },
    { "RailManual.MES.FESCycleActive",      1623, GW_TYPE_BOOL },
    { "RailManual.MES.MarrakechCycleActive",1624, GW_TYPE_BOOL },
    { "RailManual.MES.DirectionConflict",   1625, GW_TYPE_BOOL },
    { "RailManual.MES.GlobalFault",         1626, GW_TYPE_BOOL },
    { "RailManual.MES.AnimationAlive",      1627, GW_TYPE_BOOL },
    { "RailManual.MES.FESDone",             1628, GW_TYPE_BOOL },
    { "RailManual.MES.MarrakechDone",       1629, GW_TYPE_BOOL },
    { "RailManual.MES.FESCycleCount",       1630, GW_TYPE_INT32 },
    { "RailManual.MES.MarrakechCycleCount", 1631, GW_TYPE_INT32 },
    { "RailManual.MES.TotalCycleCount",     1632, GW_TYPE_INT32 },

    /* =========================================================
     * RAIL MANUAL MES - NUMERIC HEALTH / DIAGNOSTICS
     * ========================================================= */
    { "RailManual.MES.Heartbeat",           1660, GW_TYPE_INT32 },
    { "RailManual.MES.ProgramVersion",      1661, GW_TYPE_INT32 },
    { "RailManual.MES.GlobalFaultCode",     1662, GW_TYPE_INT32 },
    { "RailManual.MES.StateWord",           1663, GW_TYPE_INT32 },
    { "RailManual.MES.LastResetReason",     1664, GW_TYPE_INT32 },
    { "RailManual.MES.LastScanMs",          1665, GW_TYPE_INT32 },
    { "RailManual.MES.MaxScanMs",           1666, GW_TYPE_INT32 },
    { "RailManual.MES.WatchdogLo",          1667, GW_TYPE_INT32 },
    { "RailManual.MES.FESActiveMs",         1668, GW_TYPE_INT32 },
    { "RailManual.MES.MarrakechActiveMs",   1669, GW_TYPE_INT32 },
        /* =========================================================
     * POWERGRID PLC1 MES - ADVANCED WORDS
     * ========================================================= */
    { "PowerGrid.PLC1.MES.SourceCount",     1680, GW_TYPE_INT32 },
    { "PowerGrid.PLC1.MES.LoadCount",       1681, GW_TYPE_INT32 },
    { "PowerGrid.PLC1.MES.GridOn",          1682, GW_TYPE_INT32 },
    { "PowerGrid.PLC1.MES.LoadPercent",     1683, GW_TYPE_INT32 },
    { "PowerGrid.PLC1.MES.SourcePercent",   1684, GW_TYPE_INT32 },
    { "PowerGrid.PLC1.MES.GridState",       1685, GW_TYPE_INT32 },
    { "PowerGrid.PLC1.MES.SourceMask",      1686, GW_TYPE_INT32 },
    { "PowerGrid.PLC1.MES.LoadMask",        1687, GW_TYPE_INT32 },
    { "PowerGrid.PLC1.MES.GridReady",       1688, GW_TYPE_INT32 },
    { "PowerGrid.PLC1.MES.Overload",        1689, GW_TYPE_INT32 },
    { "PowerGrid.PLC1.MES.FaultType",       1690, GW_TYPE_INT32 },
    { "PowerGrid.PLC1.MES.Watchdog",        1691, GW_TYPE_INT32 },
    { "PowerGrid.PLC1.MES.Integrity",       1692, GW_TYPE_INT32 },

    /* =========================================================
     * POWERGRID PLC2 MES - ADVANCED WORDS
     * ========================================================= */
    { "PowerGrid.PLC2.MES.ProductionOn",        1700, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.SourceCount",         1701, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.DistributionCount",   1702, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.DistributionPercent", 1703, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.SourceMask",          1704, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.DistributionMask",    1705, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.TAPx10",              1706, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.TCPx10",              1707, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.Demandx10",           1708, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.BalanceStatus",       1709, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.BalanceAbs",          1710, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.UtilizationPercent",  1711, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.EnergyState",         1712, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.Fault",               1713, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.Watchdog",            1714, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.Integrity",           1715, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.RequestCount",        1716, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.RequestMask",         1717, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.Servedx10",           1718, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.Unservedx10",         1719, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.ServedPercent",       1720, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.FactoryDemandx10",    1721, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.HomesDemandx10",      1722, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.RailwayDemandx10",    1723, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.FactoryShare",        1724, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.HomesShare",          1725, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.RailwayShare",        1726, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.FactoryServedFlag",   1727, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.HomesServedFlag",     1728, GW_TYPE_INT32 },
    { "PowerGrid.PLC2.MES.RailwayServedFlag",   1729, GW_TYPE_INT32 },

    /* =========================================================
     * FACTORY PLC3 MES - ADVANCED WORDS
     * ========================================================= */
    { "Factory.MES.TotalCycles",          1730, GW_TYPE_INT32 },
    { "Factory.MES.TotalGood",            1731, GW_TYPE_INT32 },
    { "Factory.MES.TotalReject",          1732, GW_TYPE_INT32 },
    { "Factory.MES.ThroughputPerMin",     1733, GW_TYPE_INT32 },
    { "Factory.MES.ThroughputPerHour",    1734, GW_TYPE_INT32 },
    { "Factory.MES.QualityPercent",       1735, GW_TYPE_INT32 },
    { "Factory.MES.DowntimeSeconds",      1736, GW_TYPE_INT32 },
    { "Factory.MES.UptimeSeconds",        1737, GW_TYPE_INT32 },
    { "Factory.MES.AvailabilityPercent",  1738, GW_TYPE_INT32 },
    { "Factory.MES.TargetCycleTime",      1739, GW_TYPE_INT32 },
    { "Factory.MES.ActualCycleTime",      1740, GW_TYPE_INT32 },
    { "Factory.MES.PerformancePercent",   1741, GW_TYPE_INT32 },
    { "Factory.MES.OEE",                  1742, GW_TYPE_INT32 },
    { "Factory.MES.EnergyPerCycle",       1743, GW_TYPE_INT32 },
    { "Factory.MES.EnergyPerHour",        1744, GW_TYPE_INT32 },
    { "Factory.MES.FaultTypeAdv",         1745, GW_TYPE_INT32 },
    { "Factory.MES.WatchdogAdv",          1746, GW_TYPE_INT32 },
    { "Factory.MES.ProcessState",         1747, GW_TYPE_INT32 },
    { "Factory.MES.PumpRuntimeHours",     1748, GW_TYPE_INT32 },
    { "Factory.MES.MaintenanceDue",       1749, GW_TYPE_INT32 },
    { "Factory.MES.LoadPercent",          1750, GW_TYPE_INT32 },
    { "Factory.MES.IntegrityAdv",         1751, GW_TYPE_INT32 },

    /* =========================================================
     * RAIL AUTO PLC4 MES
     * ========================================================= */
    { "RailAuto.MES.Step",             1760, GW_TYPE_INT32 },
    { "RailAuto.MES.ProgressPercent",  1761, GW_TYPE_INT32 },
    { "RailAuto.MES.CycleActive",      1762, GW_TYPE_INT32 },
    { "RailAuto.MES.CycleDone",        1763, GW_TYPE_INT32 },
    { "RailAuto.MES.ErrorCode",        1764, GW_TYPE_INT32 },
    { "RailAuto.MES.StepTime",         1765, GW_TYPE_INT32 },
    { "RailAuto.MES.TotalTime",        1766, GW_TYPE_INT32 },
    { "RailAuto.MES.Throughput",       1767, GW_TYPE_INT32 },
    { "RailAuto.MES.Availability",     1768, GW_TYPE_INT32 },
    { "RailAuto.MES.Performance",      1769, GW_TYPE_INT32 },
    { "RailAuto.MES.Quality",          1770, GW_TYPE_INT32 },
    { "RailAuto.MES.OEE",              1771, GW_TYPE_INT32 },
    { "RailAuto.MES.Watchdog",         1772, GW_TYPE_INT32 },
    { "RailAuto.MES.State",            1773, GW_TYPE_INT32 },
    { "RailAuto.MES.FaultType",        1774, GW_TYPE_INT32 },
    { "RailAuto.MES.Integrity",        1775, GW_TYPE_INT32 },

    /* =========================================================
     * RAIL MANUAL PLC5 MES - ADVANCED WORDS
     * ========================================================= */
    { "RailManual.MES.ActiveLines",        1790, GW_TYPE_INT32 },
    { "RailManual.MES.RouteMask",          1791, GW_TYPE_INT32 },
    { "RailManual.MES.FlowCount",          1792, GW_TYPE_INT32 },
    { "RailManual.MES.FlowRate",           1793, GW_TYPE_INT32 },
    { "RailManual.MES.UtilizationPercent", 1794, GW_TYPE_INT32 },
    { "RailManual.MES.ConflictCount",      1795, GW_TYPE_INT32 },
    { "RailManual.MES.SafetyFlag",         1796, GW_TYPE_INT32 },
    { "RailManual.MES.QueueLength",        1797, GW_TYPE_INT32 },
    { "RailManual.MES.WaitTime",           1798, GW_TYPE_INT32 },
    { "RailManual.MES.Throughput",         1799, GW_TYPE_INT32 },
    { "RailManual.MES.Efficiency",         1800, GW_TYPE_INT32 },
    { "RailManual.MES.OEE",                1801, GW_TYPE_INT32 },
    { "RailManual.MES.State",              1802, GW_TYPE_INT32 },
    { "RailManual.MES.FaultTypeAdv",       1803, GW_TYPE_INT32 },
    { "RailManual.MES.WatchdogAdv",        1804, GW_TYPE_INT32 },
    { "RailManual.MES.IntegrityAdv",       1805, GW_TYPE_INT32 },
    { "RailManual.MES.LoadPercent",        1806, GW_TYPE_INT32 }
};

const size_t GATEWAY_POINTS_COUNT =
    sizeof(GATEWAY_POINTS) / sizeof(GATEWAY_POINTS[0]);
