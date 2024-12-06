-- Network Security Data Mart - Main Execution Script
-- Version: 1.0
-- For UNSW-NB15 Dataset

-- Modify file paths
-- \set features_file '/actual/path/to/UNSW-NB15_features.csv'
-- \set data_file '/actual/path/to/UNSW-NB15_head.csv'

-- Run Script
-- psql -d your_database -f main.sql

\echo 'Starting Network Security Data Mart Implementation'
\echo '==============================================='

\set ON_ERROR_STOP on
\timing on

-- Set variables for file paths (modify these according to your environment)
\set features_file '\'/path/to/UNSW-NB15_features.csv\''
\set data_file '\'/path/to/UNSW-NB15_head.csv\''

-- Create logging function
CREATE OR REPLACE FUNCTION log_step(step_name text, message text) RETURNS void AS $$
BEGIN
    RAISE NOTICE '[%] % - %', clock_timestamp()::timestamp(0), step_name, message;
END;
$$ LANGUAGE plpgsql;

-- Main execution block
DO $$
DECLARE
    v_start_time timestamp;
    v_end_time timestamp;
    v_record_count integer;
    v_error_message text;
    v_batch_id bigint;
BEGIN
    v_start_time := clock_timestamp();
    
    -- Step 1: Create database structure
    PERFORM log_step('STRUCTURE', 'Creating database structure...');
    \ir modelo-logico.sql
    PERFORM log_step('STRUCTURE', 'Database structure created successfully');

    -- Step 2: Set up staging and load source data
    PERFORM log_step('STAGING', 'Setting up staging area...');
    \ir 00_load_source_data.sql
    
    PERFORM log_step('STAGING', 'Loading source data...');
    CALL staging.load_all_data(:features_file, :data_file);
    
    SELECT COUNT(*) INTO v_record_count FROM staging.source_data;
    PERFORM log_step('STAGING', 'Loaded ' || v_record_count || ' records into staging');

    -- Step 3: Load dimensions
    PERFORM log_step('DIMENSIONS', 'Loading dimension tables...');
    \ir 01_etl_dimensions.sql
    
    CALL etl_load_dimensions(
        'UNSW-NB15',
        '2024-01-01'::timestamp,
        '2024-12-31'::timestamp
    );
    
    -- Get dimension counts for summary
    SELECT INTO v_record_count count(*) FROM DIM_SERVICE WHERE is_active = true;
    PERFORM log_step('DIMENSIONS', 'Loaded ' || v_record_count || ' active services');
    
    SELECT INTO v_record_count count(*) FROM DIM_ATTACK WHERE is_active = true;
    PERFORM log_step('DIMENSIONS', 'Loaded ' || v_record_count || ' attack categories');

    -- Step 4: Load connection facts
    PERFORM log_step('FACTS', 'Loading connection facts...');
    \ir 02_etl_connection_facts.sql
    
    CALL etl_load_connection_facts(10000);
    
    SELECT COUNT(*) INTO v_record_count FROM FACT_CONNECTION;
    PERFORM log_step('FACTS', 'Loaded ' || v_record_count || ' connection facts');

    -- Step 5: Create aggregations
    PERFORM log_step('AGGREGATIONS', 'Creating fact aggregations...');
    \ir 03_etl_aggregated_facts.sql
    
    CALL etl_aggregate_facts(
        '2024-01-01'::timestamp,
        '2024-12-31'::timestamp
    );

    -- Step 6: Run validation queries and collect results
    PERFORM log_step('VALIDATION', 'Running validation queries...');
    \ir requirements-queries.sql

    -- Generate summary report
    PERFORM log_step('SUMMARY', 'Generating implementation summary...');
    
    WITH summary AS (
        SELECT
            (SELECT COUNT(*) FROM DIM_SERVICE WHERE is_active = true) as active_services,
            (SELECT COUNT(*) FROM DIM_ATTACK WHERE is_active = true) as attack_categories,
            (SELECT COUNT(*) FROM FACT_CONNECTION) as connection_facts,
            (SELECT COUNT(*) FROM FACT_HOURLY_TRAFFIC) as hourly_aggregations,
            (SELECT COUNT(*) FROM FACT_DAILY_TRAFFIC) as daily_aggregations,
            (SELECT COUNT(*) FROM FACT_MONTHLY_TRAFFIC) as monthly_aggregations,
            (SELECT COUNT(*) FROM FACT_PORT_USAGE) as port_usage_records
    )
    SELECT
        log_step('SUMMARY', format(
            E'Implementation completed:\n' ||
            '- Active Services: %s\n' ||
            '- Attack Categories: %s\n' ||
            '- Connection Facts: %s\n' ||
            '- Hourly Aggregations: %s\n' ||
            '- Daily Aggregations: %s\n' ||
            '- Monthly Aggregations: %s\n' ||
            '- Port Usage Records: %s',
            active_services,
            attack_categories,
            connection_facts,
            hourly_aggregations,
            daily_aggregations,
            monthly_aggregations,
            port_usage_records
        ))
    FROM summary;

    -- Calculate total execution time
    v_end_time := clock_timestamp();
    PERFORM log_step('SUMMARY', 'Total execution time: ' || 
                    (extract(epoch from (v_end_time - v_start_time)))::text || ' seconds');

EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_error_message = MESSAGE_TEXT;
    PERFORM log_step('ERROR', 'Implementation failed: ' || v_error_message);
    RAISE EXCEPTION 'Implementation failed: %', v_error_message;
END;
$$;

-- Sample data analysis queries
\echo '\nSample Analysis Results'
\echo '======================='

-- Top 5 most attacked services
\echo '\nTop 5 Most Attacked Services:'
SELECT 
    s.name AS service_name,
    COUNT(*) AS total_connections,
    COUNT(*) FILTER (WHERE a.is_attack = true) AS attack_count,
    ROUND(100.0 * COUNT(*) FILTER (WHERE a.is_attack = true) / COUNT(*), 2) AS attack_percentage
FROM FACT_CONNECTION f
JOIN DIM_SERVICE s ON f.service_id = s.service_id
JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
GROUP BY s.name
ORDER BY attack_percentage DESC
LIMIT 5;

-- Attack distribution by hour
\echo '\nAttack Distribution by Hour:'
SELECT 
    t.hour,
    COUNT(*) AS total_attacks,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS percentage_of_total
FROM FACT_CONNECTION f
JOIN DIM_TIME t ON f.time_id = t.time_id
JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
WHERE a.is_attack = true
GROUP BY t.hour
ORDER BY t.hour;

-- Attack category distribution
\echo '\nAttack Category Distribution:'
SELECT 
    a.category,
    COUNT(*) AS occurrences,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) AS percentage_of_total
FROM FACT_CONNECTION f
JOIN DIM_ATTACK a ON f.attack_id = a.attack_id
WHERE a.is_attack = true
GROUP BY a.category
ORDER BY occurrences DESC;

\echo '\nImplementation and analysis complete.'