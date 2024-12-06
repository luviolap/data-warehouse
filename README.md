# Análisis de Requerimientos - UNSW-NB15 Dataset

## 1. Contexto

Para este análisis utilizaremos el dataset UNSW-NB15, que contiene registros de tráfico de red capturados por el Cyber Range Lab de UNSW Canberra. El dataset simula una mezcla de tráfico normal y malicioso, donde cada conexión está etiquetada como normal o ataque, incluyendo la categoría específica del ataque cuando aplica.

En el contexto de nuestro proyecto, simularemos que estos datos pertenecen a TechSecure, una empresa mediana que proporciona servicios de software. La empresa ha contratado una consultoría de ciberseguridad para analizar su tráfico de red y proporcionar recomendaciones para mejorar su seguridad.

Cada registro en el dataset contiene:
- Identificación de conexión: protocolo, servicios, puertos
- Métricas de tráfico: bytes y paquetes enviados/recibidos
- Información temporal: tiempo de inicio y fin
- Etiquetas: normal o ataque, tipo específico de ataque

## 2. Planteo del problema y Objetivo Principal

### Problema
TechSecure necesita entender qué servicios de su red son más vulnerables a ataques y cuáles son las características del tráfico que distinguen las conexiones normales de las maliciosas.

### Objetivo Principal
Identificar los 5 servicios más vulnerables a ataques mediante el análisis de patrones de tráfico, comparando características básicas de red entre conexiones normales y maliciosas para proporcionar recomendaciones de monitoreo específicas por servicio.

## 3. Sub-objetivos

### A. Análisis de Servicios
1. Identificar los servicios más utilizados en la red
2. Determinar servicios con mayor frecuencia de ataques
3. Calcular proporción de tráfico malicioso por servicio
4. Analizar distribución temporal de ataques por hora, día y mes

### B. Análisis de Tráfico Normal
1. Caracterizar volumen típico de datos por servicio
2. Establecer duraciones típicas de conexiones normales
3. Identificar puertos comúnmente utilizados
4. Analizar patrones de uso normal por hora, día y mes

### C. Análisis de Tráfico Malicioso
1. Medir volúmenes de datos en ataques
2. Determinar duraciones típicas de ataques
3. Identificar puertos asociados a ataques
4. Establecer patrones temporales de ataques por hora, día y mes

### D. Análisis Comparativo
1. Comparar volúmenes de tráfico normal vs malicioso
2. Contrastar duraciones de conexión
3. Identificar patrones distintivos de puertos
4. Establecer perfiles de riesgo por servicio con granularidad horaria, diaria y mensual

## 4. Consultas

### A. Análisis de Servicios
1. ¿Cuál es el ranking de servicios de red, medido por número total de conexiones?

2. Para cada servicio, contabilizar:
   - Número total de conexiones etiquetadas como ataque 
   - Número de categorías distintas de ataque

3. Para servicios con más de 1000 conexiones, calcular porcentaje de conexiones maliciosas vs normales.

4. Para cada servicio:
   - Total de ataques agrupados por hora del día
   - Total de ataques agrupados por día de la semana
   - Total de ataques agrupados por mes

### B. Análisis de Tráfico Normal
1. Para conexiones normales, calcular por servicio:
   - Total de bytes origen a destino
   - Total de bytes destino a origen
   - Total de paquetes origen a destino
   - Total de paquetes destino a origen

2. Calcular duración promedio de conexiones normales por servicio.

3. Por cada servicio en tráfico normal:
   - Top 5 puertos destino más frecuentes
   - Conteo de conexiones por puerto

4. Por servicio:
   - Contar conexiones normales agrupadas por hora del día
   - Contar conexiones normales agrupadas por día de la semana
   - Contar conexiones normales agrupadas por mes

### C. Análisis de Tráfico Malicioso
1. Para cada combinación de servicio y categoría de ataque, calcular total de bytes transferidos en ambas direcciones.

2. Por tipo de ataque y servicio:
   - Duración mínima de conexión
   - Duración promedio
   - Duración máxima

3. Identificar para cada categoría de ataque:
   - Puertos destino más utilizados
   - Frecuencia de uso de cada puerto

4. Para cada tipo de ataque:
   - Total de ataques por servicio por hora
   - Total de ataques por servicio por día
   - Total de ataques por servicio por mes

### D. Análisis Comparativo
1. Por servicio, comparar promedios entre tráfico normal y malicioso:
   - Bytes transferidos totales por hora, día y mes
   - Paquetes transferidos totales por hora, día y mes

2. Por servicio, comparar:
   - Duración promedio de conexiones normales
   - Duración promedio de conexiones maliciosas
   - Analizar variaciones por hora, día y mes

3. Para cada servicio, identificar puertos destino que aparecen exclusivamente en registros de ataque.

4. Para los 5 servicios más atacados, crear tabla resumen con:
   - Total conexiones (normales y ataques)
   - Duración promedio por tipo
   - Puertos más frecuentemente usados
   - Patrones temporales de actividad por hora, día y mes