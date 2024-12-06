-- Network Security Data Mart Complete Definition
-- Version: 2.0
-- Updated: 2024-02-08

-- ETL Control Table for tracking all data loads and aggregations
CREATE TABLE ETL_CONTROL (
    batch_id BIGSERIAL PRIMARY KEY,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    status VARCHAR(20) CHECK (status IN ('STARTED', 'RUNNING', 'COMPLETED', 'FAILED')),
    records_processed INTEGER DEFAULT 0,
    aggregation_level VARCHAR(20) CHECK (aggregation_level IN ('RAW', 'HOURLY', 'DAILY', 'MONTHLY')),
    source_system VARCHAR(50),
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- Dimension Tables with SCD Support
CREATE TABLE DIM_TIME (
    time_id INTEGER PRIMARY KEY,
    datetime TIMESTAMP NOT NULL,
    hour INTEGER NOT NULL CHECK (hour BETWEEN 0 AND 23),
    day INTEGER NOT NULL CHECK (day BETWEEN 1 AND 31),
    month INTEGER NOT NULL CHECK (month BETWEEN 1 AND 12),
    year INTEGER NOT NULL CHECK (year >= 2000),
    day_type VARCHAR(10) NOT NULL CHECK (day_type IN ('WEEKDAY', 'WEEKEND', 'HOLIDAY')),
    day_name VARCHAR(10) NOT NULL,
    month_name VARCHAR(10) NOT NULL,
    is_business_hour BOOLEAN NOT NULL,
    is_peak_hour BOOLEAN NOT NULL,
    week_of_year INTEGER NOT NULL,
    quarter INTEGER NOT NULL CHECK (quarter BETWEEN 1 AND 4),
    batch_id BIGINT NOT NULL REFERENCES ETL_CONTROL(batch_id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_datetime UNIQUE (datetime)
);

CREATE TABLE DIM_SERVICE (
    service_id INTEGER PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    protocol VARCHAR(50) NOT NULL,
    service_type VARCHAR(50) NOT NULL,
    category VARCHAR(50) NOT NULL,
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    valid_from TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_to TIMESTAMP,
    version INTEGER NOT NULL DEFAULT 1,
    batch_id BIGINT NOT NULL REFERENCES ETL_CONTROL(batch_id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    CONSTRAINT uk_service_version UNIQUE (name, valid_from, version)
);

CREATE TABLE DIM_PORT (
    port_id INTEGER PRIMARY KEY,
    port_number INTEGER NOT NULL CHECK (port_number BETWEEN 0 AND 65535),
    range_type VARCHAR(20) NOT NULL CHECK (range_type IN ('SYSTEM', 'USER', 'DYNAMIC')),
    default_service VARCHAR(100),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    valid_from TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_to TIMESTAMP,
    version INTEGER NOT NULL DEFAULT 1,
    batch_id BIGINT NOT NULL REFERENCES ETL_CONTROL(batch_id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    CONSTRAINT uk_port_version UNIQUE (port_number, valid_from, version)
);

CREATE TABLE DIM_STATE (
    state_id INTEGER PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    category VARCHAR(50) NOT NULL,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    batch_id BIGINT NOT NULL REFERENCES ETL_CONTROL(batch_id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_state_name UNIQUE (name)
);

CREATE TABLE DIM_PROTOCOL (
    protocol_id INTEGER PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    type VARCHAR(50) NOT NULL,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    batch_id BIGINT NOT NULL REFERENCES ETL_CONTROL(batch_id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_protocol_name UNIQUE (name)
);

CREATE TABLE DIM_ATTACK (
    attack_id INTEGER PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    is_attack BOOLEAN NOT NULL,
    severity INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 5),
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    batch_id BIGINT NOT NULL REFERENCES ETL_CONTROL(batch_id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_attack_category UNIQUE (category)
);

-- Fact Tables with Partitioning
CREATE TABLE FACT_CONNECTION (
    connection_id BIGSERIAL,
    time_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    source_port_id INTEGER NOT NULL,
    dest_port_id INTEGER NOT NULL,
    state_id INTEGER NOT NULL,
    protocol_id INTEGER NOT NULL,
    attack_id INTEGER NOT NULL,
    duration NUMERIC(10,3) NOT NULL CHECK (duration >= 0),
    source_bytes BIGINT NOT NULL CHECK (source_bytes >= 0),
    dest_bytes BIGINT NOT NULL CHECK (dest_bytes >= 0),
    source_packets INTEGER NOT NULL CHECK (source_packets >= 0),
    dest_packets INTEGER NOT NULL CHECK (dest_packets >= 0),
    source_load NUMERIC(10,3) CHECK (source_load >= 0),
    dest_load NUMERIC(10,3) CHECK (dest_load >= 0),
    source_ttl INTEGER CHECK (source_ttl >= 0),
    dest_ttl INTEGER CHECK (dest_ttl >= 0),
    source_loss INTEGER CHECK (source_loss >= 0),
    dest_loss INTEGER CHECK (dest_loss >= 0),
    ct_srv_src INTEGER CHECK (ct_srv_src >= 0),
    ct_srv_dst INTEGER CHECK (ct_srv_dst >= 0),
    ct_state_ttl INTEGER CHECK (ct_state_ttl >= 0),
    batch_id BIGINT NOT NULL REFERENCES ETL_CONTROL(batch_id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_connection PRIMARY KEY (connection_id, time_id),
    FOREIGN KEY (time_id) REFERENCES DIM_TIME(time_id),
    FOREIGN KEY (service_id) REFERENCES DIM_SERVICE(service_id),
    FOREIGN KEY (source_port_id) REFERENCES DIM_PORT(port_id),
    FOREIGN KEY (dest_port_id) REFERENCES DIM_PORT(port_id),
    FOREIGN KEY (state_id) REFERENCES DIM_STATE(state_id),
    FOREIGN KEY (protocol_id) REFERENCES DIM_PROTOCOL(protocol_id),
    FOREIGN KEY (attack_id) REFERENCES DIM_ATTACK(attack_id)
) PARTITION BY RANGE (time_id);

CREATE TABLE FACT_HOURLY_TRAFFIC (
    hourly_traffic_id BIGSERIAL,
    time_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    protocol_id INTEGER NOT NULL,
    attack_id INTEGER NOT NULL,
    total_connections INTEGER NOT NULL DEFAULT 0 CHECK (total_connections >= 0),
    normal_connections INTEGER NOT NULL DEFAULT 0 CHECK (normal_connections >= 0),
    attack_connections INTEGER NOT NULL DEFAULT 0 CHECK (attack_connections >= 0),
    avg_duration NUMERIC(10,3) CHECK (avg_duration >= 0),
    avg_duration_normal NUMERIC(10,3) CHECK (avg_duration_normal >= 0),
    avg_duration_attack NUMERIC(10,3) CHECK (avg_duration_attack >= 0),
    total_bytes_normal BIGINT NOT NULL DEFAULT 0 CHECK (total_bytes_normal >= 0),
    total_bytes_attack BIGINT NOT NULL DEFAULT 0 CHECK (total_bytes_attack >= 0),
    total_packets_normal INTEGER NOT NULL DEFAULT 0 CHECK (total_packets_normal >= 0),
    total_packets_attack INTEGER NOT NULL DEFAULT 0 CHECK (total_packets_attack >= 0),
    avg_bytes_per_conn NUMERIC(10,3) CHECK (avg_bytes_per_conn >= 0),
    avg_bytes_per_attack NUMERIC(10,3) CHECK (avg_bytes_per_attack >= 0),
    avg_load_normal NUMERIC(10,3) CHECK (avg_load_normal >= 0),
    avg_load_attack NUMERIC(10,3) CHECK (avg_load_attack >= 0),
    distinct_services INTEGER NOT NULL DEFAULT 0 CHECK (distinct_services >= 0),
    distinct_ports INTEGER NOT NULL DEFAULT 0 CHECK (distinct_ports >= 0),
    peak_hour_connections INTEGER,
    batch_id BIGINT NOT NULL REFERENCES ETL_CONTROL(batch_id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_hourly_traffic PRIMARY KEY (hourly_traffic_id, time_id),
    CONSTRAINT uk_hourly_traffic UNIQUE (time_id, service_id, protocol_id, attack_id),
    FOREIGN KEY (time_id) REFERENCES DIM_TIME(time_id),
    FOREIGN KEY (service_id) REFERENCES DIM_SERVICE(service_id),
    FOREIGN KEY (protocol_id) REFERENCES DIM_PROTOCOL(protocol_id),
    FOREIGN KEY (attack_id) REFERENCES DIM_ATTACK(attack_id)
) PARTITION BY RANGE (time_id);

CREATE TABLE FACT_DAILY_TRAFFIC (
    daily_traffic_id BIGSERIAL,
    time_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    protocol_id INTEGER NOT NULL,
    attack_id INTEGER NOT NULL,
    total_connections INTEGER NOT NULL DEFAULT 0,
    normal_connections INTEGER NOT NULL DEFAULT 0,
    attack_connections INTEGER NOT NULL DEFAULT 0,
    avg_duration NUMERIC(10,3),
    total_bytes BIGINT NOT NULL DEFAULT 0,
    total_packets INTEGER NOT NULL DEFAULT 0,
    peak_hour_connections INTEGER,
    peak_hour INTEGER CHECK (peak_hour BETWEEN 0 AND 23),
    distinct_attack_types INTEGER NOT NULL DEFAULT 0,
    attack_percentage NUMERIC(5,2),
    batch_id BIGINT NOT NULL REFERENCES ETL_CONTROL(batch_id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_daily_traffic PRIMARY KEY (daily_traffic_id, time_id),
    CONSTRAINT uk_daily_traffic UNIQUE (time_id, service_id, protocol_id, attack_id),
    FOREIGN KEY (time_id) REFERENCES DIM_TIME(time_id),
    FOREIGN KEY (service_id) REFERENCES DIM_SERVICE(service_id),
    FOREIGN KEY (protocol_id) REFERENCES DIM_PROTOCOL(protocol_id),
    FOREIGN KEY (attack_id) REFERENCES DIM_ATTACK(attack_id)
) PARTITION BY RANGE (time_id);

CREATE TABLE FACT_MONTHLY_TRAFFIC (
    monthly_traffic_id BIGSERIAL,
    time_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    protocol_id INTEGER NOT NULL,
    attack_id INTEGER NOT NULL,
    total_connections INTEGER NOT NULL DEFAULT 0,
    normal_connections INTEGER NOT NULL DEFAULT 0,
    attack_connections INTEGER NOT NULL DEFAULT 0,
    avg_duration NUMERIC(10,3),
    total_bytes BIGINT NOT NULL DEFAULT 0,
    total_packets INTEGER NOT NULL DEFAULT 0,
    peak_day_connections INTEGER,
    peak_day INTEGER CHECK (peak_day BETWEEN 1 AND 31),
    distinct_attack_types INTEGER NOT NULL DEFAULT 0,
    attack_percentage NUMERIC(5,2),
    batch_id BIGINT NOT NULL REFERENCES ETL_CONTROL(batch_id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_monthly_traffic PRIMARY KEY (monthly_traffic_id, time_id),
    CONSTRAINT uk_monthly_traffic UNIQUE (time_id, service_id, protocol_id, attack_id),
    FOREIGN KEY (time_id) REFERENCES DIM_TIME(time_id),
    FOREIGN KEY (service_id) REFERENCES DIM_SERVICE(service_id),
    FOREIGN KEY (protocol_id) REFERENCES DIM_PROTOCOL(protocol_id),
    FOREIGN KEY (attack_id) REFERENCES DIM_ATTACK(attack_id)
) PARTITION BY RANGE (time_id);

CREATE TABLE FACT_SERVICE_STATS (
    service_stats_id BIGSERIAL,
    service_id INTEGER NOT NULL,
    time_id INTEGER NOT NULL,
    protocol_id INTEGER NOT NULL,
    attack_id INTEGER NOT NULL,
    total_connections INTEGER NOT NULL DEFAULT 0,
    normal_connections INTEGER NOT NULL DEFAULT 0,
    attack_connections INTEGER NOT NULL DEFAULT 0,
    distinct_attack_types INTEGER NOT NULL DEFAULT 0,
    attack_percentage NUMERIC(5,2) NOT NULL,
    avg_duration_normal NUMERIC(10,3),
    avg_duration_attack NUMERIC(10,3),
    duration_ratio NUMERIC(10,3),
    total_bytes_normal BIGINT NOT NULL DEFAULT 0,
    total_bytes_attack BIGINT NOT NULL DEFAULT 0,
    bytes_ratio NUMERIC(10,3),
    total_packets_normal INTEGER NOT NULL DEFAULT 0,
    total_packets_attack INTEGER NOT NULL DEFAULT 0,
    packets_ratio NUMERIC(10,3),
    avg_bytes_per_conn NUMERIC(10,3),
    avg_bytes_per_attack NUMERIC(10,3),
    peak_hour_normal INTEGER CHECK (peak_hour_normal BETWEEN 0 AND 23),
    peak_hour_attack INTEGER CHECK (peak_hour_attack BETWEEN 0 AND 23),
    exclusive_attack_ports INTEGER NOT NULL DEFAULT 0,
    batch_id BIGINT NOT NULL REFERENCES ETL_CONTROL(batch_id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_service_stats PRIMARY KEY (service_stats_id, time_id),
    CONSTRAINT uk_service_stats UNIQUE (service_id, time_id, protocol_id, attack_id),
    FOREIGN KEY (service_id) REFERENCES DIM_SERVICE(service_id),
    FOREIGN KEY (time_id) REFERENCES DIM_TIME(time_id),
    FOREIGN KEY (protocol_id) REFERENCES DIM_PROTOCOL(protocol_id),
    FOREIGN KEY (attack_id) REFERENCES DIM_ATTACK(attack_id)
) PARTITION BY RANGE (time_id);

CREATE TABLE FACT_PORT_USAGE (
    port_usage_id BIGSERIAL,
    port_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    protocol_id INTEGER NOT NULL,
    attack_id INTEGER NOT NULL,
    time_id INTEGER NOT NULL,
    total_usage INTEGER NOT NULL DEFAULT 0,
    normal_usage INTEGER NOT NULL DEFAULT 0,
    attack_usage INTEGER NOT NULL DEFAULT 0,
    usage_percentage NUMERIC(5,2) NOT NULL,
    attack_percentage NUMERIC(5,2) NOT NULL,
    exclusive_to_attacks BOOLEAN NOT NULL DEFAULT FALSE,
    primary_attack_type VARCHAR(50),
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    distinct_services INTEGER NOT NULL DEFAULT 0,
    batch_id BIGINT NOT NULL REFERENCES ETL_CONTROL(batch_id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_port_usage PRIMARY KEY (port_usage_id, time_id),
    CONSTRAINT uk_port_usage UNIQUE (port_id, service_id, protocol_id, attack_id, time_id),
    CONSTRAINT chk_port_usage_total CHECK (total_usage = normal_usage + attack_usage),
    CONSTRAINT chk_port_usage_dates CHECK (first_seen <= last_seen),
    FOREIGN KEY (port_id) REFERENCES DIM_PORT(port_id),
    FOREIGN KEY (service_id) REFERENCES DIM_SERVICE(service_id),
    FOREIGN KEY (protocol_id) REFERENCES DIM_PROTOCOL(protocol_id),
    FOREIGN KEY (attack_id) REFERENCES DIM_ATTACK(attack_id),
    FOREIGN KEY (time_id) REFERENCES DIM_TIME(time_id)
) PARTITION BY RANGE (time_id);

-- Comprehensive Indexing Strategy

-- Time Dimension Indexes
CREATE INDEX IF NOT EXISTS idx_time_components ON DIM_TIME (year, month, day, hour);
CREATE INDEX IF NOT EXISTS idx_time_business ON DIM_TIME (is_business_hour) WHERE is_business_hour = TRUE;
CREATE INDEX IF NOT EXISTS idx_time_peak ON DIM_TIME (is_peak_hour) WHERE is_peak_hour = TRUE;
CREATE INDEX IF NOT EXISTS idx_time_day_type ON DIM_TIME (day_type);

-- Service Dimension Indexes
CREATE INDEX IF NOT EXISTS idx_service_active ON DIM_SERVICE(service_id) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_service_risk ON DIM_SERVICE(risk_level, is_active);
CREATE INDEX IF NOT EXISTS idx_service_category ON DIM_SERVICE(category, service_type, is_active);
CREATE INDEX IF NOT EXISTS idx_service_temporal ON DIM_SERVICE(valid_from, valid_to) WHERE is_active = TRUE;

-- Port Dimension Indexes
CREATE INDEX IF NOT EXISTS idx_port_number ON DIM_PORT(port_number) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_port_range ON DIM_PORT(range_type, is_active);
CREATE INDEX IF NOT EXISTS idx_port_temporal ON DIM_PORT(valid_from, valid_to) WHERE is_active = TRUE;

-- Attack Pattern Indexes
CREATE INDEX IF NOT EXISTS idx_attack_severity ON DIM_ATTACK(severity, is_active);
CREATE INDEX IF NOT EXISTS idx_attack_category ON DIM_ATTACK(category) WHERE is_active = TRUE;

-- Connection Fact Indexes
CREATE INDEX IF NOT EXISTS idx_conn_time_service ON FACT_CONNECTION(time_id, service_id);
CREATE INDEX IF NOT EXISTS idx_conn_service_attack ON FACT_CONNECTION(service_id, attack_id);
CREATE INDEX IF NOT EXISTS idx_conn_ports ON FACT_CONNECTION(source_port_id, dest_port_id);
CREATE INDEX IF NOT EXISTS idx_conn_duration ON FACT_CONNECTION(duration);
CREATE INDEX IF NOT EXISTS idx_conn_bytes ON FACT_CONNECTION(source_bytes, dest_bytes);
CREATE INDEX IF NOT EXISTS idx_conn_packets ON FACT_CONNECTION(source_packets, dest_packets);
CREATE INDEX IF NOT EXISTS idx_conn_total_bytes ON FACT_CONNECTION((source_bytes + dest_bytes));
CREATE INDEX IF NOT EXISTS idx_conn_total_packets ON FACT_CONNECTION((source_packets + dest_packets));
CREATE INDEX IF NOT EXISTS idx_conn_analysis ON FACT_CONNECTION(time_id, service_id, attack_id) 
    INCLUDE (duration, source_bytes, dest_bytes);

-- Hourly Traffic Indexes
CREATE INDEX IF NOT EXISTS idx_hourly_time_service ON FACT_HOURLY_TRAFFIC(time_id, service_id);
CREATE INDEX IF NOT EXISTS idx_hourly_attack_pattern ON FACT_HOURLY_TRAFFIC(service_id, attack_id, time_id) 
    WHERE attack_connections > 0;
CREATE INDEX IF NOT EXISTS idx_hourly_volume ON FACT_HOURLY_TRAFFIC(total_connections DESC);

-- Daily Traffic Indexes
CREATE INDEX IF NOT EXISTS idx_daily_time_service ON FACT_DAILY_TRAFFIC(time_id, service_id);
CREATE INDEX IF NOT EXISTS idx_daily_attack_pattern ON FACT_DAILY_TRAFFIC(service_id, attack_id) 
    WHERE attack_percentage > 10;
CREATE INDEX IF NOT EXISTS idx_daily_peak ON FACT_DAILY_TRAFFIC(peak_hour_connections DESC);

-- Monthly Traffic Indexes
CREATE INDEX IF NOT EXISTS idx_monthly_time_service ON FACT_MONTHLY_TRAFFIC(time_id, service_id);
CREATE INDEX IF NOT EXISTS idx_monthly_attack_trend ON FACT_MONTHLY_TRAFFIC(service_id, attack_id) 
    WHERE distinct_attack_types > 1;
CREATE INDEX IF NOT EXISTS idx_monthly_volume ON FACT_MONTHLY_TRAFFIC(total_connections DESC);

-- Service Stats Indexes
CREATE INDEX IF NOT EXISTS idx_stats_service_time ON FACT_SERVICE_STATS(service_id, time_id);
CREATE INDEX IF NOT EXISTS idx_stats_attack_analysis ON FACT_SERVICE_STATS(attack_percentage DESC, service_id)
    INCLUDE (distinct_attack_types, exclusive_attack_ports);
CREATE INDEX IF NOT EXISTS idx_stats_performance ON FACT_SERVICE_STATS(service_id, time_id)
    INCLUDE (avg_duration_normal, avg_duration_attack, bytes_ratio);

-- Port Usage Indexes
CREATE INDEX IF NOT EXISTS idx_port_usage_analysis ON FACT_PORT_USAGE(port_id, service_id, time_id);
CREATE INDEX IF NOT EXISTS idx_port_attack_pattern ON FACT_PORT_USAGE(attack_percentage DESC)
    WHERE exclusive_to_attacks = TRUE;
CREATE INDEX IF NOT EXISTS idx_port_temporal ON FACT_PORT_USAGE(first_seen, last_seen);

-- Materialized Views for Common Analysis Patterns

-- Hourly Service Performance
CREATE MATERIALIZED VIEW MV_HOURLY_SERVICE_PERFORMANCE AS
SELECT 
    s.name as service_name,
    s.service_type,
    s.risk_level,
    t.hour,
    t.is_business_hour,
    SUM(ht.total_connections) as total_connections,
    SUM(ht.attack_connections) as attack_connections,
    ROUND(100.0 * SUM(ht.attack_connections) / NULLIF(SUM(ht.total_connections), 0), 2) as avg_attack_percentage,
    SUM(ht.total_bytes_normal + ht.total_bytes_attack) as total_bytes,
    AVG(ht.avg_duration) as avg_duration
FROM FACT_HOURLY_TRAFFIC ht
JOIN DIM_SERVICE s ON ht.service_id = s.service_id
JOIN DIM_TIME t ON ht.time_id = t.time_id
WHERE s.is_active = TRUE
GROUP BY s.name, s.service_type, s.risk_level, t.hour, t.is_business_hour;

-- Daily Attack Patterns
CREATE MATERIALIZED VIEW MV_DAILY_ATTACK_PATTERNS AS
SELECT 
    s.name as service_name,
    a.category as attack_category,
    t.day_type,
    dt.peak_hour,
    SUM(dt.attack_connections) as total_attacks,
    AVG(dt.attack_percentage) as avg_attack_percentage,
    COUNT(DISTINCT dt.distinct_attack_types) as attack_varieties
FROM FACT_DAILY_TRAFFIC dt
JOIN DIM_SERVICE s ON dt.service_id = s.service_id
JOIN DIM_ATTACK a ON dt.attack_id = a.attack_id
JOIN DIM_TIME t ON dt.time_id = t.time_id
WHERE s.is_active = TRUE AND a.is_active = TRUE
GROUP BY s.name, a.category, t.day_type, dt.peak_hour;

-- Service Risk Profile
CREATE MATERIALIZED VIEW MV_SERVICE_RISK_PROFILE AS
SELECT 
    s.name as service_name,
    s.service_type,
    s.risk_level,
    COUNT(DISTINCT ss.distinct_attack_types) as total_attack_types,
    AVG(ss.attack_percentage) as avg_attack_percentage,
    MAX(ss.peak_hour_attack) as common_attack_hour,
    SUM(ss.exclusive_attack_ports) as exclusive_attack_ports,
    AVG(ss.duration_ratio) as avg_duration_ratio,
    AVG(ss.bytes_ratio) as avg_bytes_ratio
FROM FACT_SERVICE_STATS ss
JOIN DIM_SERVICE s ON ss.service_id = s.service_id
WHERE s.is_active = TRUE
GROUP BY s.name, s.service_type, s.risk_level;

-- Port Security Analysis
CREATE MATERIALIZED VIEW MV_PORT_SECURITY_ANALYSIS AS
SELECT 
    p.port_number,
    p.range_type,
    s.name as service_name,
    COUNT(DISTINCT pu.primary_attack_type) as attack_types,
    SUM(CASE WHEN pu.exclusive_to_attacks THEN 1 ELSE 0 END) as exclusive_attack_count,
    AVG(pu.attack_percentage) as avg_attack_percentage,
    MAX(pu.last_seen) as last_attack_seen
FROM FACT_PORT_USAGE pu
JOIN DIM_PORT p ON pu.port_id = p.port_id
JOIN DIM_SERVICE s ON pu.service_id = s.service_id
WHERE p.is_active = TRUE AND s.is_active = TRUE
GROUP BY p.port_number, p.range_type, s.name;

-- Refresh Strategy for Materialized Views
CREATE OR REPLACE PROCEDURE REFRESH_MATERIALIZED_VIEWS()
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY MV_HOURLY_SERVICE_PERFORMANCE;
    REFRESH MATERIALIZED VIEW CONCURRENTLY MV_DAILY_ATTACK_PATTERNS;
    REFRESH MATERIALIZED VIEW CONCURRENTLY MV_SERVICE_RISK_PROFILE;
    REFRESH MATERIALIZED VIEW CONCURRENTLY MV_PORT_SECURITY_ANALYSIS;
END;
$$;

-- Create indexes on materialized views
CREATE INDEX idx_mv_hourly_perf_service ON MV_HOURLY_SERVICE_PERFORMANCE(service_name, hour);
CREATE INDEX idx_mv_attack_patterns_service ON MV_DAILY_ATTACK_PATTERNS(service_name, attack_category);
CREATE INDEX idx_mv_risk_profile_level ON MV_SERVICE_RISK_PROFILE(risk_level, avg_attack_percentage DESC);
CREATE INDEX idx_mv_port_security_attack ON MV_PORT_SECURITY_ANALYSIS(avg_attack_percentage DESC);

-- Create partitions for fact tables
DO $$
DECLARE
    v_year INTEGER := 2015;
    v_month INTEGER := 1;
    v_start_time TIMESTAMP;
    v_end_time TIMESTAMP;
    v_start_id INTEGER;
    v_end_id INTEGER;
    v_partition_name TEXT;
BEGIN
    -- Create partitions for January 2015 (since we know our data is from Jan 22, 2015)
    v_start_time := DATE_TRUNC('month', ('2015-01-01'::date))::timestamp;
    v_end_time := v_start_time + INTERVAL '1 month';
    
    -- Convert timestamps to time_ids (Unix timestamps)
    v_start_id := EXTRACT(EPOCH FROM v_start_time)::INTEGER;
    v_end_id := EXTRACT(EPOCH FROM v_end_time)::INTEGER;
    
    -- Create partition name with proper zero-padding for month
    v_partition_name := '_' || v_year || '_' || LPAD(v_month::text, 2, '0');
    
    -- Create partition for FACT_HOURLY_TRAFFIC if not exists
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS fact_hourly_traffic%s 
        PARTITION OF fact_hourly_traffic 
        FOR VALUES FROM (%s) TO (%s)',
        v_partition_name, v_start_id, v_end_id
    );

    -- Create partition for FACT_DAILY_TRAFFIC if not exists
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS fact_daily_traffic%s 
        PARTITION OF fact_daily_traffic 
        FOR VALUES FROM (%s) TO (%s)',
        v_partition_name, v_start_id, v_end_id
    );

    -- Create partition for FACT_MONTHLY_TRAFFIC if not exists
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS fact_monthly_traffic%s 
        PARTITION OF fact_monthly_traffic 
        FOR VALUES FROM (%s) TO (%s)',
        v_partition_name, v_start_id, v_end_id
    );

    -- Create partition for FACT_SERVICE_STATS if not exists
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS fact_service_stats%s 
        PARTITION OF fact_service_stats 
        FOR VALUES FROM (%s) TO (%s)',
        v_partition_name, v_start_id, v_end_id
    );

    -- Create partition for FACT_PORT_USAGE if not exists
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS fact_port_usage%s 
        PARTITION OF fact_port_usage 
        FOR VALUES FROM (%s) TO (%s)',
        v_partition_name, v_start_id, v_end_id
    );

    RAISE NOTICE 'Created partitions for year % month % (time_id from % to %)', 
        v_year, v_month, v_start_id, v_end_id;

EXCEPTION WHEN duplicate_table THEN
    RAISE NOTICE 'Some partitions already exist - continuing...';
END $$;