-- Vista enriquecida con metadatos de puntos de medida
CREATE OR REPLACE VIEW v_trafico_enriquecido AS
SELECT t.*,
       p.descripcion AS desc_punto,
       p.cod_cent,
       p.distrito,
       p.barrio
FROM trafico_realtime t
LEFT JOIN puntos_medida p
ON t.idelem = p.id;

-- Resumen de tráfico por minuto, subárea y nivel de servicio
CREATE OR REPLACE VIEW v_trafico_resumen AS
SELECT date_trunc('minute', fecha_hora) AS minuto,
       subarea,
       nivelServicio,
       avg(intensidad) AS intensidad_media,
       avg(ocupacion)  AS ocupacion_media
FROM trafico_realtime
GROUP BY 1,2,3;
