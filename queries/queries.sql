-- Network Security Data Mart - Requirements Validation Queries
-- Version: 1.0
-- Based on requirements document analysis needs

-- Common query helpers
WITH latest_etl AS (
    SELECT batch_id 
    FROM ETL_CONTROL 
    WHERE status = 'COMPLETED' 
    ORDER BY end_time DESC 
    LIMIT 1
),
last_24h AS (
    SELECT t.time_id
    FROM DIM_TIME t
    WHERE t.datetime >= (
        SELECT MAX(t2.datetime) - INTERVAL '24 hours'
        FROM DIM_TIME t2
    )
)

---------------------------------------
-- A. Service Analysis
---------------------------------------

-- A1. Ranking of network services
SELECT 
    s.name AS service_name,
    COUNT(*) AS total_connections,
    SUM(CASE WHEN a.is_attack THEN 1 ELSE 0 END) AS attack_connections,
    ROUND(100.0 * SUM(CASE WHEN a.is_attack THEN 1 ELSE 0 END) / COUNT(*), 2) AS attack_percentage,
    AVG(f.duration) AS avg_duration,
    SUM(f.source_bytes + f.dest_bytes) AS total_bytes
FROM FACT_CONNECTION f
JOIN DIM_SERVICE s ON f.service_id = s.service_id
JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
GROUP BY s.name
ORDER BY total_connections DESC;

-- A2. Attack statistics by service
SELECT 
    s.name AS service_name,
    a.category AS attack_type,
    COUNT(*) AS attack_count,
    AVG(f.duration) AS avg_duration,
    SUM(f.source_bytes + f.dest_bytes) AS total_bytes
FROM FACT_CONNECTION f
JOIN DIM_SERVICE s ON f.service_id = s.service_id
JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
WHERE a.is_attack = TRUE
GROUP BY s.name, a.category
ORDER BY s.name, attack_count DESC;

-- A3. High-volume service analysis
SELECT 
    s.name AS service_name,
    dt.day_type,
    t.hour,
    COUNT(*) AS connections,
    SUM(CASE WHEN a.is_attack THEN 1 ELSE 0 END) AS attacks
FROM FACT_CONNECTION f
JOIN DIM_SERVICE s ON f.service_id = s.service_id
JOIN DIM_TIME t ON f.time_id = t.time_id
JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
WHERE t.time_id IN (SELECT time_id FROM last_24h)
GROUP BY s.name, dt.day_type, t.hour
ORDER BY s.name, t.hour;

---------------------------------------
-- B. Traffic Pattern Analysis
---------------------------------------

-- B1. Normal traffic characteristics
SELECT 
    s.name AS service_name,
    ht.total_connections,
    ht.normal_connections,
    ROUND(ht.avg_duration_normal::numeric, 2) AS avg_duration,
    ht.total_bytes_normal,
    ht.total_packets_normal,
    ht.avg_load_normal
FROM FACT_HOURLY_TRAFFIC ht
JOIN DIM_SERVICE s ON ht.service_id = s.service_id
JOIN DIM_TIME t ON ht.time_id = t.time_id
WHERE t.time_id IN (SELECT time_id FROM last_24h)
ORDER BY s.name, t.hour;

-- B2. Port usage patterns
SELECT 
    p.port_number,
    p.range_type,
    pu.total_usage,
    pu.normal_usage,
    pu.attack_usage,
    pu.attack_percentage,
    pu.exclusive_to_attacks
FROM FACT_PORT_USAGE pu
JOIN DIM_PORT p ON pu.port_id = p.port_id
WHERE pu.attack_percentage > 0
ORDER BY pu.attack_percentage DESC;

-- B3. Time-based traffic patterns
SELECT 
    t.hour,
    t.is_business_hour,
    SUM(ht.total_connections) AS total_connections,
    SUM(ht.attack_connections) AS attack_connections,
    ROUND(100.0 * SUM(ht.attack_connections) / SUM(ht.total_connections), 2) AS attack_percentage
FROM FACT_HOURLY_TRAFFIC ht
JOIN DIM_TIME t ON ht.time_id = t.time_id
WHERE t.time_id IN (SELECT time_id FROM last_24h)
GROUP BY t.hour, t.is_business_hour
ORDER BY t.hour;

---------------------------------------
-- C. Attack Pattern Analysis
---------------------------------------

-- C1. Attack type distribution
SELECT 
    a.category AS attack_type,
    a.severity,
    COUNT(*) AS occurrences,
    COUNT(DISTINCT s.service_id) AS affected_services,
    AVG(f.duration) AS avg_duration
FROM FACT_CONNECTION f
JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
JOIN DIM_SERVICE s ON f.service_id = s.service_id
WHERE a.is_attack = TRUE
GROUP BY a.category, a.severity
ORDER BY occurrences DESC;

-- C2. Temporal attack patterns
SELECT 
    t.hour,
    a.category AS attack_type,
    COUNT(*) AS attack_count,
    AVG(f.duration) AS avg_duration,
    SUM(f.source_bytes + f.dest_bytes) AS total_bytes
FROM FACT_CONNECTION f
JOIN DIM_TIME t ON f.time_id = t.time_id
JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
WHERE a.is_attack = TRUE 
AND t.time_id IN (SELECT time_id FROM last_24h)
GROUP BY t.hour, a.category
ORDER BY t.hour, attack_count DESC;

-- C3. Attack service correlation
SELECT 
    s.name AS service_name,
    p.name AS protocol,
    a.category AS attack_type,
    COUNT(*) AS occurrences,
    AVG(f.duration) AS avg_duration
FROM FACT_CONNECTION f
JOIN DIM_SERVICE s ON f.service_id = s.service_id
JOIN DIM_PROTOCOL p ON f.protocol_id = p.protocol_id
JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
WHERE a.is_attack = TRUE
GROUP BY s.name, p.name, a.category
ORDER BY occurrences DESC;

---------------------------------------
-- D. Comparative Analysis
---------------------------------------

-- D1. Normal vs Attack Traffic Comparison
SELECT 
    s.name AS service_name,
    ss.total_connections,
    ss.normal_connections,
    ss.attack_connections,
    ROUND(ss.attack_percentage::numeric, 2) AS attack_percentage,
    ROUND(ss.avg_duration_normal::numeric, 2) AS avg_duration_normal,
    ROUND(ss.avg_duration_attack::numeric, 2) AS avg_duration_attack,
    ss.total_bytes_normal,
    ss.total_bytes_attack
FROM FACT_SERVICE_STATS ss
JOIN DIM_SERVICE s ON ss.service_id = s.service_id
WHERE ss.time_id IN (
    SELECT MAX(time_id) 
    FROM DIM_TIME
)
ORDER BY ss.total_connections DESC;

-- D2. Service Risk Profile
SELECT 
    s.name AS service_name,
    s.risk_level,
    mrp.total_attack_types,
    mrp.avg_attack_percentage,
    mrp.common_attack_hour,
    mrp.exclusive_attack_ports
FROM MV_SERVICE_RISK_PROFILE mrp
JOIN DIM_SERVICE s ON mrp.service_name = s.name
ORDER BY mrp.avg_attack_percentage DESC;

-- D3. Port Usage Analysis
SELECT 
    mpa.port_number,
    mpa.range_type,
    mpa.service_name,
    mpa.attack_types,
    mpa.exclusive_attack_count,
    mpa.avg_attack_percentage,
    mpa.last_attack_seen
FROM MV_PORT_SECURITY_ANALYSIS mpa
WHERE mpa.avg_attack_percentage > 0
ORDER BY mpa.avg_attack_percentage DESC;

-- D4. Overall Security Summary
SELECT 
    COUNT(DISTINCT s.service_id) AS total_services,
    COUNT(DISTINCT CASE WHEN a.is_attack THEN f.attack_id END) AS total_attack_types,
    ROUND(100.0 * COUNT(CASE WHEN a.is_attack THEN 1 END) / COUNT(*), 2) AS overall_attack_percentage,
    COUNT(DISTINCT CASE WHEN pu.exclusive_to_attacks THEN pu.port_id END) AS exclusive_attack_ports
FROM FACT_CONNECTION f
JOIN DIM_SERVICE s ON f.service_id = s.service_id
JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
LEFT JOIN FACT_PORT_USAGE pu ON f.service_id = pu.service_id;