-- Network Security Data Mart - Aggregated Facts ETL
-- Version: 1.0
-- For UNSW-NB15 Dataset

-- Create procedure to aggregate hourly traffic
CREATE OR REPLACE PROCEDURE aggregate_hourly_traffic(
    p_batch_id BIGINT,
    p_start_time TIMESTAMP,
    p_end_time TIMESTAMP
) LANGUAGE plpgsql AS $$
DECLARE
    v_processed INTEGER;
BEGIN
    INSERT INTO FACT_HOURLY_TRAFFIC (
        time_id,
        service_id,
        protocol_id,
        attack_id,
        total_connections,
        normal_connections,
        attack_connections,
        avg_duration,
        avg_duration_normal,
        avg_duration_attack,
        total_bytes_normal,
        total_bytes_attack,
        total_packets_normal,
        total_packets_attack,
        avg_bytes_per_conn,
        avg_bytes_per_attack,
        avg_load_normal,
        avg_load_attack,
        distinct_services,
        distinct_ports,
        peak_hour_connections,
        batch_id
    )
    SELECT 
        f.time_id,
        f.service_id,
        f.protocol_id,
        f.attack_id,
        COUNT(*) as total_connections,
        COUNT(*) FILTER (WHERE a.is_attack = FALSE) as normal_connections,
        COUNT(*) FILTER (WHERE a.is_attack = TRUE) as attack_connections,
        AVG(f.duration) as avg_duration,
        AVG(f.duration) FILTER (WHERE a.is_attack = FALSE) as avg_duration_normal,
        AVG(f.duration) FILTER (WHERE a.is_attack = TRUE) as avg_duration_attack,
        SUM(f.source_bytes + f.dest_bytes) FILTER (WHERE a.is_attack = FALSE) as total_bytes_normal,
        SUM(f.source_bytes + f.dest_bytes) FILTER (WHERE a.is_attack = TRUE) as total_bytes_attack,
        SUM(f.source_packets + f.dest_packets) FILTER (WHERE a.is_attack = FALSE) as total_packets_normal,
        SUM(f.source_packets + f.dest_packets) FILTER (WHERE a.is_attack = TRUE) as total_packets_attack,
        AVG(f.source_bytes + f.dest_bytes) FILTER (WHERE a.is_attack = FALSE) as avg_bytes_per_conn,
        AVG(f.source_bytes + f.dest_bytes) FILTER (WHERE a.is_attack = TRUE) as avg_bytes_per_attack,
        AVG(f.source_load) FILTER (WHERE a.is_attack = FALSE) as avg_load_normal,
        AVG(f.source_load) FILTER (WHERE a.is_attack = TRUE) as avg_load_attack,
        COUNT(DISTINCT f.service_id) as distinct_services,
        COUNT(DISTINCT f.source_port_id) + COUNT(DISTINCT f.dest_port_id) as distinct_ports,
        MAX(COUNT(*)) OVER (PARTITION BY f.service_id, t.hour) as peak_hour_connections,
        p_batch_id
    FROM FACT_CONNECTION f
    JOIN DIM_TIME t ON f.time_id = t.time_id
    JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
    WHERE t.datetime BETWEEN p_start_time AND p_end_time
    GROUP BY f.time_id, f.service_id, f.protocol_id, f.attack_id, t.hour;
    
    GET DIAGNOSTICS v_processed = ROW_COUNT;
    RAISE NOTICE 'Processed % hourly aggregations', v_processed;
END;
$$;

-- Create procedure to aggregate daily traffic
CREATE OR REPLACE PROCEDURE aggregate_daily_traffic(
    p_batch_id BIGINT,
    p_start_time TIMESTAMP,
    p_end_time TIMESTAMP
) LANGUAGE plpgsql AS $$
DECLARE
    v_processed INTEGER;
BEGIN
    INSERT INTO FACT_DAILY_TRAFFIC (
        time_id,
        service_id,
        protocol_id,
        attack_id,
        total_connections,
        normal_connections,
        attack_connections,
        avg_duration,
        total_bytes,
        total_packets,
        peak_hour_connections,
        peak_hour,
        distinct_attack_types,
        attack_percentage,
        batch_id
    )
    WITH daily_stats AS (
        SELECT 
            date_trunc('day', t.datetime) as day,
            f.service_id,
            f.protocol_id,
            f.attack_id,
            COUNT(*) as total_connections,
            COUNT(*) FILTER (WHERE a.is_attack = FALSE) as normal_connections,
            COUNT(*) FILTER (WHERE a.is_attack = TRUE) as attack_connections,
            AVG(f.duration) as avg_duration,
            SUM(f.source_bytes + f.dest_bytes) as total_bytes,
            SUM(f.source_packets + f.dest_packets) as total_packets,
            MAX(COUNT(*)) OVER (PARTITION BY f.service_id, t.hour) as peak_hour_connections,
            t.hour as peak_hour,
            COUNT(DISTINCT a.category) FILTER (WHERE a.is_attack = TRUE) as distinct_attack_types,
            ROUND(100.0 * COUNT(*) FILTER (WHERE a.is_attack = TRUE) / NULLIF(COUNT(*), 0), 2) as attack_percentage
        FROM FACT_CONNECTION f
        JOIN DIM_TIME t ON f.time_id = t.time_id
        JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
        WHERE t.datetime BETWEEN p_start_time AND p_end_time
        GROUP BY 
            date_trunc('day', t.datetime),
            f.service_id,
            f.protocol_id,
            f.attack_id,
            t.hour
    )
    SELECT 
        MIN(dt.time_id) as time_id,
        ds.service_id,
        ds.protocol_id,
        ds.attack_id,
        ds.total_connections,
        ds.normal_connections,
        ds.attack_connections,
        ds.avg_duration,
        ds.total_bytes,
        ds.total_packets,
        ds.peak_hour_connections,
        ds.peak_hour,
        ds.distinct_attack_types,
        ds.attack_percentage,
        p_batch_id
    FROM daily_stats ds
    JOIN DIM_TIME dt ON date_trunc('day', dt.datetime) = ds.day
    GROUP BY 
        ds.day,
        ds.service_id,
        ds.protocol_id,
        ds.attack_id,
        ds.total_connections,
        ds.normal_connections,
        ds.attack_connections,
        ds.avg_duration,
        ds.total_bytes,
        ds.total_packets,
        ds.peak_hour_connections,
        ds.peak_hour,
        ds.distinct_attack_types,
        ds.attack_percentage;

    GET DIAGNOSTICS v_processed = ROW_COUNT;
    RAISE NOTICE 'Processed % daily aggregations', v_processed;
END;
$$;

-- Create procedure to aggregate monthly traffic
CREATE OR REPLACE PROCEDURE aggregate_monthly_traffic(
    p_batch_id BIGINT,
    p_start_time TIMESTAMP,
    p_end_time TIMESTAMP
) LANGUAGE plpgsql AS $$
DECLARE
    v_processed INTEGER;
BEGIN
    INSERT INTO FACT_MONTHLY_TRAFFIC (
        time_id,
        service_id,
        protocol_id,
        attack_id,
        total_connections,
        normal_connections,
        attack_connections,
        avg_duration,
        total_bytes,
        total_packets,
        peak_day_connections,
        peak_day,
        distinct_attack_types,
        attack_percentage,
        batch_id
    )
    WITH monthly_stats AS (
        SELECT 
            date_trunc('month', t.datetime) as month,
            f.service_id,
            f.protocol_id,
            f.attack_id,
            COUNT(*) as total_connections,
            COUNT(*) FILTER (WHERE a.is_attack = FALSE) as normal_connections,
            COUNT(*) FILTER (WHERE a.is_attack = TRUE) as attack_connections,
            AVG(f.duration) as avg_duration,
            SUM(f.source_bytes + f.dest_bytes) as total_bytes,
            SUM(f.source_packets + f.dest_packets) as total_packets,
            MAX(COUNT(*)) OVER (PARTITION BY f.service_id, t.day) as peak_day_connections,
            t.day as peak_day,
            COUNT(DISTINCT a.category) FILTER (WHERE a.is_attack = TRUE) as distinct_attack_types,
            ROUND(100.0 * COUNT(*) FILTER (WHERE a.is_attack = TRUE) / NULLIF(COUNT(*), 0), 2) as attack_percentage
        FROM FACT_CONNECTION f
        JOIN DIM_TIME t ON f.time_id = t.time_id
        JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
        WHERE t.datetime BETWEEN p_start_time AND p_end_time
        GROUP BY 
            date_trunc('month', t.datetime),
            f.service_id,
            f.protocol_id,
            f.attack_id,
            t.day
    )
    SELECT 
        MIN(dt.time_id) as time_id,
        ms.service_id,
        ms.protocol_id,
        ms.attack_id,
        ms.total_connections,
        ms.normal_connections,
        ms.attack_connections,
        ms.avg_duration,
        ms.total_bytes,
        ms.total_packets,
        ms.peak_day_connections,
        ms.peak_day,
        ms.distinct_attack_types,
        ms.attack_percentage,
        p_batch_id
    FROM monthly_stats ms
    JOIN DIM_TIME dt ON date_trunc('month', dt.datetime) = ms.month
    GROUP BY 
        ms.month,
        ms.service_id,
        ms.protocol_id,
        ms.attack_id,
        ms.total_connections,
        ms.normal_connections,
        ms.attack_connections,
        ms.avg_duration,
        ms.total_bytes,
        ms.total_packets,
        ms.peak_day_connections,
        ms.peak_day,
        ms.distinct_attack_types,
        ms.attack_percentage;

    GET DIAGNOSTICS v_processed = ROW_COUNT;
    RAISE NOTICE 'Processed % monthly aggregations', v_processed;
END;
$$;

-- Create main procedure to orchestrate all aggregations
CREATE OR REPLACE PROCEDURE etl_aggregate_facts(
    p_start_time TIMESTAMP,
    p_end_time TIMESTAMP
) LANGUAGE plpgsql AS $$
DECLARE
    v_batch_id BIGINT;
    v_error_message TEXT;
BEGIN
    -- Initialize ETL batch
    INSERT INTO ETL_CONTROL (
        start_time,
        status,
        source_system,
        aggregation_level
    ) VALUES (
        CURRENT_TIMESTAMP,
        'STARTED',
        'UNSW-NB15',
        'AGGREGATED'
    ) RETURNING batch_id INTO v_batch_id;

    -- Process aggregations
    BEGIN
        -- Hourly aggregations
        CALL aggregate_hourly_traffic(v_batch_id, p_start_time, p_end_time);
        
        -- Daily aggregations
        CALL aggregate_daily_traffic(v_batch_id, p_start_time, p_end_time);
        
        -- Monthly aggregations
        CALL aggregate_monthly_traffic(v_batch_id, p_start_time, p_end_time);
        
        -- Refresh materialized views
        CALL REFRESH_MATERIALIZED_VIEWS();
        
        -- Update ETL control status
        UPDATE ETL_CONTROL 
        SET status = 'COMPLETED',
            end_time = CURRENT_TIMESTAMP
        WHERE batch_id = v_batch_id;
        
        RAISE NOTICE 'Fact aggregation completed successfully';
        
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_error_message = MESSAGE_TEXT;
        
        UPDATE ETL_CONTROL 
        SET status = 'FAILED',
            end_time = CURRENT_TIMESTAMP,
            error_message = v_error_message
        WHERE batch_id = v_batch_id;
        
        RAISE EXCEPTION 'Fact aggregation failed: %', v_error_message;
    END;
END;
$$;

-- Example usage:
COMMENT ON PROCEDURE etl_aggregate_facts IS 
$doc$
Aggregate connection facts into hourly, daily, and monthly summaries.

Example usage:
CALL etl_aggregate_facts(
    '2024-01-01 00:00:00'::TIMESTAMP,
    '2024-01-31 23:59:59'::TIMESTAMP
);
$doc$;
