-- Complete OLAP Queries for Network Security Analysis
-- Based on Requirements Document

-- Common Time Windows
WITH latest_etl AS (
    SELECT batch_id 
    FROM ETL_CONTROL 
    WHERE status = 'COMPLETED' 
    ORDER BY end_time DESC 
    LIMIT 1
),
latest_time AS (
    SELECT time_id, datetime
    FROM DIM_TIME 
    WHERE batch_id = (SELECT batch_id FROM latest_etl)
    ORDER BY datetime DESC 
    LIMIT 1
),
last_24h AS (
    SELECT time_id
    FROM DIM_TIME
    WHERE datetime >= ((SELECT datetime FROM latest_time) - INTERVAL '24 hours')
)

---------------------------------------
-- A. Análisis de Servicios
---------------------------------------

-- A1. Ranking de servicios por volumen
SELECT 
    s.name,
    s.service_type,
    ss.total_connections,
    (ss.total_bytes_normal + ss.total_bytes_attack) as total_bytes,
    (ss.total_packets_normal + ss.total_packets_attack) as total_packets,
    ROUND((ss.attack_percentage)::numeric, 2) as attack_rate
FROM FACT_SERVICE_STATS ss
JOIN DIM_SERVICE s ON ss.service_id = s.service_id
WHERE s.is_active = TRUE
    AND ss.time_id = (SELECT time_id FROM latest_time)
ORDER BY ss.total_connections DESC;

-- A2. Ataques por servicio
SELECT 
    s.name,
    s.service_type,
    ss.attack_connections,
    ss.distinct_attack_types,
    ROUND(ss.attack_percentage::numeric, 2) as attack_percentage
FROM FACT_SERVICE_STATS ss
JOIN DIM_SERVICE s ON ss.service_id = s.service_id
WHERE s.is_active = TRUE
    AND ss.time_id = (SELECT time_id FROM latest_time)
ORDER BY ss.attack_connections DESC;

-- A3. Porcentaje ataques por servicio
SELECT 
    s.name,
    s.service_type,
    ss.total_connections,
    ROUND(ss.attack_percentage::numeric, 2) as attack_percentage,
    ss.distinct_attack_types
FROM FACT_SERVICE_STATS ss
JOIN DIM_SERVICE s ON ss.service_id = s.service_id
WHERE s.is_active = TRUE 
    AND ss.time_id = (SELECT time_id FROM latest_time)
    AND ss.total_connections > 1000
ORDER BY ss.attack_percentage DESC;

-- A4. Distribución horaria de ataques
SELECT 
    s.name,
    t.hour,
    ht.attack_connections,
    ht.total_bytes_attack,
    ht.total_packets_attack,
    ROUND(ht.avg_duration_attack::numeric, 2) as avg_duration_attack
FROM FACT_HOURLY_TRAFFIC ht
JOIN DIM_SERVICE s ON ht.service_id = s.service_id
JOIN DIM_TIME t ON ht.time_id = t.time_id
WHERE s.is_active = TRUE
    AND ht.time_id IN (SELECT time_id FROM last_24h)
ORDER BY s.name, t.hour;

---------------------------------------
-- B. Análisis de Tráfico Normal
---------------------------------------

-- B1. Métricas de tráfico normal
SELECT 
    s.name,
    s.service_type,
    ss.total_bytes_normal,
    ss.total_packets_normal,
    ROUND(ss.avg_duration_normal::numeric, 2) as avg_duration,
    ROUND(ss.avg_bytes_per_conn::numeric, 2) as avg_bytes_per_conn
FROM FACT_SERVICE_STATS ss
JOIN DIM_SERVICE s ON ss.service_id = s.service_id
WHERE s.is_active = TRUE
    AND ss.time_id = (SELECT time_id FROM latest_time);

-- B2. Duraciones de conexiones normales
SELECT 
    s.name,
    ROUND(ss.avg_duration_normal::numeric, 2) as avg_duration,
    ss.peak_hour_normal,
    ss.normal_connections
FROM FACT_SERVICE_STATS ss
JOIN DIM_SERVICE s ON ss.service_id = s.service_id
WHERE s.is_active = TRUE
    AND ss.time_id = (SELECT time_id FROM latest_time);

-- B3. Top puertos en tráfico normal
SELECT 
    s.name,
    p.port_number,
    p.range_type,
    pu.normal_usage,
    ROUND(pu.usage_percentage::numeric, 2) as usage_percentage
FROM FACT_PORT_USAGE pu
JOIN DIM_SERVICE s ON pu.service_id = s.service_id
JOIN DIM_PORT p ON pu.port_id = p.port_id
WHERE s.is_active = TRUE
    AND p.is_active = TRUE
    AND pu.time_id = (SELECT time_id FROM latest_time)
    AND pu.normal_usage > 0
ORDER BY pu.normal_usage DESC
LIMIT 5;

-- B4. Conexiones normales por hora
SELECT 
    s.name,
    t.hour,
    ht.normal_connections,
    ht.total_bytes_normal,
    ht.total_packets_normal,
    ROUND(ht.avg_duration_normal::numeric, 2) as avg_duration
FROM FACT_HOURLY_TRAFFIC ht
JOIN DIM_SERVICE s ON ht.service_id = s.service_id
JOIN DIM_TIME t ON ht.time_id = t.time_id
WHERE s.is_active = TRUE
    AND ht.time_id IN (SELECT time_id FROM last_24h)
ORDER BY s.name, t.hour;

---------------------------------------
-- C. Análisis de Tráfico Malicioso
---------------------------------------

-- C1. Bytes por tipo de ataque
SELECT 
    s.name,
    a.category,
    ht.total_bytes_attack,
    ht.total_packets_attack,
    ROUND(ht.avg_duration_attack::numeric, 2) as avg_duration,
    ROUND(ht.avg_bytes_per_attack::numeric, 2) as avg_bytes_per_attack
FROM FACT_HOURLY_TRAFFIC ht
JOIN DIM_SERVICE s ON ht.service_id = s.service_id
JOIN DIM_ATTACK a ON ht.attack_id = a.attack_id
WHERE s.is_active = TRUE
    AND a.is_active = TRUE
    AND ht.time_id = (SELECT time_id FROM latest_time)
    AND ht.attack_connections > 0;

-- C2. Duraciones por tipo de ataque
SELECT 
    s.name,
    a.category,
    ROUND(ss.avg_duration_attack::numeric, 2) as avg_duration,
    ss.attack_connections,
    ROUND(ss.avg_bytes_per_attack::numeric, 2) as avg_bytes_per_attack
FROM FACT_SERVICE_STATS ss
JOIN DIM_SERVICE s ON ss.service_id = s.service_id
JOIN DIM_ATTACK a ON ss.attack_id = a.attack_id
WHERE s.is_active = TRUE
    AND a.is_active = TRUE
    AND ss.time_id = (SELECT time_id FROM latest_time)
    AND ss.attack_connections > 0;

-- C3. Puertos usados en ataques
SELECT 
    p.port_number,
    p.range_type,
    pu.attack_usage,
    ROUND(pu.attack_percentage::numeric, 2) as attack_percentage,
    pu.primary_attack_type,
    pu.first_seen,
    pu.last_seen
FROM FACT_PORT_USAGE pu
JOIN DIM_PORT p ON pu.port_id = p.port_id
WHERE p.is_active = TRUE
    AND pu.time_id = (SELECT time_id FROM latest_time)
    AND pu.attack_usage > 0
ORDER BY pu.attack_usage DESC;

-- C4. Ataques por hora
SELECT 
    s.name,
    t.hour,
    a.category as attack_type,
    ht.attack_connections,
    ht.total_bytes_attack,
    ht.total_packets_attack,
    ROUND(ht.avg_duration_attack::numeric, 2) as avg_duration
FROM FACT_HOURLY_TRAFFIC ht
JOIN DIM_SERVICE s ON ht.service_id = s.service_id
JOIN DIM_TIME t ON ht.time_id = t.time_id
JOIN DIM_ATTACK a ON ht.attack_id = a.attack_id
WHERE s.is_active = TRUE
    AND ht.time_id IN (SELECT time_id FROM last_24h)
ORDER BY s.name, t.hour;

---------------------------------------
-- D. Análisis Comparativo
---------------------------------------

-- D1. Comparación de volúmenes
SELECT 
    s.name,
    ss.normal_connections,
    ss.attack_connections,
    ss.total_bytes_normal,
    ss.total_bytes_attack,
    ROUND(ss.bytes_ratio::numeric, 2) as bytes_ratio,
    ss.total_packets_normal,
    ss.total_packets_attack,
    ROUND(ss.packets_ratio::numeric, 2) as packets_ratio
FROM FACT_SERVICE_STATS ss
JOIN DIM_SERVICE s ON ss.service_id = s.service_id
WHERE s.is_active = TRUE
    AND ss.time_id = (SELECT time_id FROM latest_time);

-- D2. Comparación de duraciones
SELECT 
    s.name,
    ROUND(ss.avg_duration_normal::numeric, 2) as avg_duration_normal,
    ROUND(ss.avg_duration_attack::numeric, 2) as avg_duration_attack,
    ROUND(ss.duration_ratio::numeric, 2) as duration_ratio,
    ss.peak_hour_normal,
    ss.peak_hour_attack
FROM FACT_SERVICE_STATS ss
JOIN DIM_SERVICE s ON ss.service_id = s.service_id
WHERE s.is_active = TRUE
    AND ss.time_id = (SELECT time_id FROM latest_time);

-- D3. Puertos exclusivos de ataques
SELECT 
    s.name,
    p.port_number,
    p.range_type,
    pu.attack_usage,
    pu.primary_attack_type,
    pu.first_seen,
    pu.last_seen
FROM FACT_PORT_USAGE pu
JOIN DIM_SERVICE s ON pu.service_id = s.service_id
JOIN DIM_PORT p ON pu.port_id = p.port_id
WHERE s.is_active = TRUE
    AND p.is_active = TRUE
    AND pu.exclusive_to_attacks = TRUE
    AND pu.time_id = (SELECT time_id FROM latest_time)
ORDER BY pu.attack_usage DESC;

-- D4. Resumen top 5 servicios vulnerables
SELECT 
    s.name,
    s.service_type,
    ROUND(ss.attack_percentage::numeric, 2) as attack_percentage,
    ROUND(ss.bytes_ratio::numeric, 2) as bytes_ratio,
    ROUND(ss.packets_ratio::numeric, 2) as packets_ratio,
    ROUND(ss.duration_ratio::numeric, 2) as duration_ratio,
    ss.peak_hour_attack,
    ss.exclusive_attack_ports,
    ss.distinct_attack_types
FROM FACT_SERVICE_STATS ss
JOIN DIM_SERVICE s ON ss.service_id = s.service_id
WHERE s.is_active = TRUE
    AND ss.time_id = (SELECT time_id FROM latest_time)
ORDER BY ss.attack_percentage DESC
LIMIT 5;