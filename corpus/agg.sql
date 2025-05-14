SELECT 
    count(*) as total,
    sum(value) as sum_value,
    avg(value) as avg_value
FROM my_table
GROUP BY category;