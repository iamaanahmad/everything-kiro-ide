# Monitoring and Observability Setup

Comprehensive guide to implementing monitoring, logging, alerting, and observability for modern applications and infrastructure.

## Observability Stack

### Prometheus + Grafana Setup

```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus:/etc/prometheus
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'
    restart: unless-stopped
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_INSTALL_PLUGINS=grafana-piechart-panel,grafana-worldmap-panel
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning
      - ./monitoring/grafana/dashboards:/var/lib/grafana/dashboards
    restart: unless-stopped
    networks:
      - monitoring

  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./monitoring/alertmanager:/etc/alertmanager
      - alertmanager_data:/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
      - '--web.external-url=http://localhost:9093'
    restart: unless-stopped
    networks:
      - monitoring

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    restart: unless-stopped
    networks:
      - monitoring

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    container_name: cadvisor
    ports:
      - "8080:8080"
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:rw
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
      - /dev/disk/:/dev/disk:ro
    privileged: true
    restart: unless-stopped
    networks:
      - monitoring

volumes:
  prometheus_data:
  grafana_data:
  alertmanager_data:

networks:
  monitoring:
    driver: bridge
```

### Prometheus Configuration

```yaml
# monitoring/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'production'
    replica: 'A'

rule_files:
  - "alert_rules.yml"
  - "recording_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  # Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  # Node Exporter
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
    scrape_interval: 30s

  # cAdvisor
  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']
    scrape_interval: 30s

  # Application metrics
  - job_name: 'myapp'
    static_configs:
      - targets: ['app:3000']
    metrics_path: '/metrics'
    scrape_interval: 15s

  # Database metrics
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  # Redis metrics
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  # Nginx metrics
  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']

  # Kubernetes API Server (if running on K8s)
  - job_name: 'kubernetes-apiservers'
    kubernetes_sd_configs:
      - role: endpoints
    scheme: https
    tls_config:
      ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    relabel_configs:
      - source_labels: [__meta_kubernetes_namespace, __meta_kubernetes_service_name, __meta_kubernetes_endpoint_port_name]
        action: keep
        regex: default;kubernetes;https

  # Kubernetes Pods
  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
      - action: labelmap
        regex: __meta_kubernetes_pod_label_(.+)
      - source_labels: [__meta_kubernetes_namespace]
        action: replace
        target_label: kubernetes_namespace
      - source_labels: [__meta_kubernetes_pod_name]
        action: replace
        target_label: kubernetes_pod_name
```

### Alert Rules

```yaml
# monitoring/prometheus/alert_rules.yml
groups:
- name: infrastructure.rules
  rules:
  - alert: InstanceDown
    expr: up == 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Instance {{ $labels.instance }} down"
      description: "{{ $labels.instance }} of job {{ $labels.job }} has been down for more than 5 minutes."

  - alert: HighCPUUsage
    expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage on {{ $labels.instance }}"
      description: "CPU usage is above 80% for more than 5 minutes on {{ $labels.instance }}"

  - alert: HighMemoryUsage
    expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 85
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage on {{ $labels.instance }}"
      description: "Memory usage is above 85% for more than 5 minutes on {{ $labels.instance }}"

  - alert: DiskSpaceLow
    expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100 < 10
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Low disk space on {{ $labels.instance }}"
      description: "Disk space is below 10% on {{ $labels.instance }}"

- name: application.rules
  rules:
  - alert: HighErrorRate
    expr: |
      (
        rate(http_requests_total{status=~"5.."}[5m]) /
        rate(http_requests_total[5m])
      ) * 100 > 5
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value | humanizePercentage }} for {{ $labels.instance }}"

  - alert: HighLatency
    expr: |
      histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High latency detected"
      description: "95th percentile latency is {{ $value }}s for {{ $labels.instance }}"

  - alert: DatabaseConnectionsHigh
    expr: pg_stat_activity_count > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High database connections"
      description: "Database has {{ $value }} active connections"

  - alert: RedisMemoryHigh
    expr: redis_memory_used_bytes / redis_memory_max_bytes * 100 > 90
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Redis memory usage high"
      description: "Redis memory usage is {{ $value }}% on {{ $labels.instance }}"
```

### Alertmanager Configuration

```yaml
# monitoring/alertmanager/alertmanager.yml
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@mycompany.com'
  smtp_auth_username: 'alerts@mycompany.com'
  smtp_auth_password: 'password'

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'default'
  routes:
  - match:
      severity: critical
    receiver: 'critical-alerts'
    group_wait: 5s
    repeat_interval: 30m
  - match:
      severity: warning
    receiver: 'warning-alerts'
    repeat_interval: 2h

receivers:
- name: 'default'
  email_configs:
  - to: 'team@mycompany.com'
    subject: 'Alert: {{ .GroupLabels.alertname }}'
    body: |
      {{ range .Alerts }}
      Alert: {{ .Annotations.summary }}
      Description: {{ .Annotations.description }}
      Labels: {{ range .Labels.SortedPairs }}{{ .Name }}={{ .Value }} {{ end }}
      {{ end }}

- name: 'critical-alerts'
  email_configs:
  - to: 'oncall@mycompany.com'
    subject: 'CRITICAL: {{ .GroupLabels.alertname }}'
    body: |
      {{ range .Alerts }}
      CRITICAL ALERT: {{ .Annotations.summary }}
      Description: {{ .Annotations.description }}
      Labels: {{ range .Labels.SortedPairs }}{{ .Name }}={{ .Value }} {{ end }}
      {{ end }}
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
    channel: '#alerts'
    title: 'CRITICAL: {{ .GroupLabels.alertname }}'
    text: |
      {{ range .Alerts }}
      {{ .Annotations.summary }}
      {{ .Annotations.description }}
      {{ end }}

- name: 'warning-alerts'
  email_configs:
  - to: 'team@mycompany.com'
    subject: 'Warning: {{ .GroupLabels.alertname }}'
    body: |
      {{ range .Alerts }}
      Warning: {{ .Annotations.summary }}
      Description: {{ .Annotations.description }}
      {{ end }}

inhibit_rules:
- source_match:
    severity: 'critical'
  target_match:
    severity: 'warning'
  equal: ['alertname', 'cluster', 'service']
```

## Application Metrics

### Node.js Application Instrumentation

```typescript
// metrics.ts
import express from 'express'
import promClient from 'prom-client'

// Create a Registry
const register = new promClient.Registry()

// Add default metrics
promClient.collectDefaultMetrics({
  register,
  prefix: 'myapp_',
  gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5]
})

// Custom metrics
const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10]
})

const httpRequestsTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code']
})

const activeConnections = new promClient.Gauge({
  name: 'active_connections',
  help: 'Number of active connections'
})

const databaseConnectionPool = new promClient.Gauge({
  name: 'database_connection_pool_size',
  help: 'Current size of database connection pool',
  labelNames: ['pool_name', 'state']
})

const businessMetrics = new promClient.Counter({
  name: 'business_events_total',
  help: 'Total number of business events',
  labelNames: ['event_type', 'status']
})

// Register metrics
register.registerMetric(httpRequestDuration)
register.registerMetric(httpRequestsTotal)
register.registerMetric(activeConnections)
register.registerMetric(databaseConnectionPool)
register.registerMetric(businessMetrics)

// Middleware to collect HTTP metrics
export const metricsMiddleware = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const start = Date.now()
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000
    const route = req.route?.path || req.path
    
    httpRequestDuration
      .labels(req.method, route, res.statusCode.toString())
      .observe(duration)
    
    httpRequestsTotal
      .labels(req.method, route, res.statusCode.toString())
      .inc()
  })
  
  next()
}

// Metrics endpoint
export const metricsHandler = async (req: express.Request, res: express.Response) => {
  res.set('Content-Type', register.contentType)
  res.end(await register.metrics())
}

// Helper functions to update custom metrics
export const updateActiveConnections = (count: number) => {
  activeConnections.set(count)
}

export const updateDatabasePool = (poolName: string, active: number, idle: number) => {
  databaseConnectionPool.labels(poolName, 'active').set(active)
  databaseConnectionPool.labels(poolName, 'idle').set(idle)
}

export const recordBusinessEvent = (eventType: string, status: 'success' | 'failure') => {
  businessMetrics.labels(eventType, status).inc()
}

// Usage in main app
const app = express()

// Apply metrics middleware
app.use(metricsMiddleware)

// Metrics endpoint
app.get('/metrics', metricsHandler)

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() })
})

// Example business logic with metrics
app.post('/api/users', async (req, res) => {
  try {
    const user = await createUser(req.body)
    recordBusinessEvent('user_creation', 'success')
    res.status(201).json(user)
  } catch (error) {
    recordBusinessEvent('user_creation', 'failure')
    res.status(500).json({ error: 'Failed to create user' })
  }
})
```

### Python Application Instrumentation

```python
# metrics.py
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from flask import Flask, request, Response
import time
import functools

# Metrics
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP request latency',
    ['method', 'endpoint']
)

ACTIVE_CONNECTIONS = Gauge(
    'active_connections',
    'Number of active connections'
)

DATABASE_CONNECTIONS = Gauge(
    'database_connections',
    'Database connection pool status',
    ['pool_name', 'state']
)

BUSINESS_EVENTS = Counter(
    'business_events_total',
    'Business events counter',
    ['event_type', 'status']
)

def track_requests(f):
    """Decorator to track request metrics"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        
        try:
            response = f(*args, **kwargs)
            status = getattr(response, 'status_code', 200)
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.endpoint or 'unknown',
                status=status
            ).inc()
            
            return response
        except Exception as e:
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.endpoint or 'unknown',
                status=500
            ).inc()
            raise
        finally:
            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=request.endpoint or 'unknown'
            ).observe(time.time() - start_time)
    
    return decorated_function

# Flask app setup
app = Flask(__name__)

@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    if hasattr(request, 'start_time'):
        REQUEST_LATENCY.labels(
            method=request.method,
            endpoint=request.endpoint or 'unknown'
        ).observe(time.time() - request.start_time)
        
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.endpoint or 'unknown',
            status=response.status_code
        ).inc()
    
    return response

@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

@app.route('/health')
def health():
    return {'status': 'healthy', 'timestamp': time.time()}

@app.route('/api/users', methods=['POST'])
@track_requests
def create_user():
    try:
        # Business logic here
        user = create_user_logic(request.json)
        BUSINESS_EVENTS.labels(event_type='user_creation', status='success').inc()
        return user, 201
    except Exception as e:
        BUSINESS_EVENTS.labels(event_type='user_creation', status='failure').inc()
        return {'error': 'Failed to create user'}, 500

# Helper functions
def update_active_connections(count):
    ACTIVE_CONNECTIONS.set(count)

def update_database_connections(pool_name, active, idle):
    DATABASE_CONNECTIONS.labels(pool_name=pool_name, state='active').set(active)
    DATABASE_CONNECTIONS.labels(pool_name=pool_name, state='idle').set(idle)
```

## Logging Setup

### Structured Logging with ELK Stack

```yaml
# docker-compose.logging.yml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.5.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
      - xpack.security.enabled=false
      - xpack.security.enrollment.enabled=false
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
    networks:
      - logging

  logstash:
    image: docker.elastic.co/logstash/logstash:8.5.0
    container_name: logstash
    ports:
      - "5044:5044"
      - "9600:9600"
    volumes:
      - ./logging/logstash/pipeline:/usr/share/logstash/pipeline
      - ./logging/logstash/config:/usr/share/logstash/config
    environment:
      - "LS_JAVA_OPTS=-Xmx512m -Xms512m"
    depends_on:
      - elasticsearch
    networks:
      - logging

  kibana:
    image: docker.elastic.co/kibana/kibana:8.5.0
    container_name: kibana
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - XPACK_SECURITY_ENABLED=false
    depends_on:
      - elasticsearch
    networks:
      - logging

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.5.0
    container_name: filebeat
    user: root
    volumes:
      - ./logging/filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - filebeat_data:/usr/share/filebeat/data
    depends_on:
      - logstash
    networks:
      - logging

volumes:
  elasticsearch_data:
  filebeat_data:

networks:
  logging:
    driver: bridge
```

### Application Logging Configuration

```typescript
// logger.ts
import winston from 'winston'
import { ElasticsearchTransport } from 'winston-elasticsearch'

// Define log levels
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4
}

// Define colors for each level
const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white'
}

winston.addColors(colors)

// Custom format for structured logging
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf((info) => {
    const { timestamp, level, message, ...meta } = info
    return JSON.stringify({
      timestamp,
      level,
      message,
      service: 'myapp',
      environment: process.env.NODE_ENV || 'development',
      ...meta
    })
  })
)

// Create transports
const transports = [
  // Console transport for development
  new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize({ all: true }),
      winston.format.simple()
    )
  }),
  
  // File transport for all logs
  new winston.transports.File({
    filename: 'logs/app.log',
    format: logFormat
  }),
  
  // File transport for error logs
  new winston.transports.File({
    filename: 'logs/error.log',
    level: 'error',
    format: logFormat
  })
]

// Add Elasticsearch transport for production
if (process.env.NODE_ENV === 'production') {
  transports.push(
    new ElasticsearchTransport({
      level: 'info',
      clientOpts: {
        node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200'
      },
      index: 'myapp-logs',
      format: logFormat
    })
  )
}

// Create logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  levels,
  format: logFormat,
  transports,
  exitOnError: false
})

// Create request logger middleware
export const requestLogger = (req: any, res: any, next: any) => {
  const start = Date.now()
  
  res.on('finish', () => {
    const duration = Date.now() - start
    
    logger.http('HTTP Request', {
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration,
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      userId: req.user?.id,
      requestId: req.id
    })
  })
  
  next()
}

// Structured logging helpers
export const logError = (message: string, error: Error, context?: any) => {
  logger.error(message, {
    error: {
      name: error.name,
      message: error.message,
      stack: error.stack
    },
    ...context
  })
}

export const logInfo = (message: string, context?: any) => {
  logger.info(message, context)
}

export const logWarn = (message: string, context?: any) => {
  logger.warn(message, context)
}

export const logDebug = (message: string, context?: any) => {
  logger.debug(message, context)
}

export default logger
```

## Distributed Tracing

### OpenTelemetry Setup

```typescript
// tracing.ts
import { NodeSDK } from '@opentelemetry/sdk-node'
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node'
import { JaegerExporter } from '@opentelemetry/exporter-jaeger'
import { Resource } from '@opentelemetry/resources'
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions'

// Configure the SDK
const sdk = new NodeSDK({
  resource: new Resource({
    [SemanticResourceAttributes.SERVICE_NAME]: 'myapp',
    [SemanticResourceAttributes.SERVICE_VERSION]: process.env.APP_VERSION || '1.0.0',
    [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: process.env.NODE_ENV || 'development'
  }),
  traceExporter: new JaegerExporter({
    endpoint: process.env.JAEGER_ENDPOINT || 'http://localhost:14268/api/traces'
  }),
  instrumentations: [
    getNodeAutoInstrumentations({
      '@opentelemetry/instrumentation-fs': {
        enabled: false // Disable file system instrumentation
      }
    })
  ]
})

// Initialize the SDK
sdk.start()

// Custom tracing utilities
import { trace, context, SpanStatusCode } from '@opentelemetry/api'

const tracer = trace.getTracer('myapp', '1.0.0')

export const createSpan = (name: string, fn: (span: any) => Promise<any>) => {
  return tracer.startActiveSpan(name, async (span) => {
    try {
      const result = await fn(span)
      span.setStatus({ code: SpanStatusCode.OK })
      return result
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : 'Unknown error'
      })
      span.recordException(error as Error)
      throw error
    } finally {
      span.end()
    }
  })
}

// Usage example
export const processOrder = async (orderId: string) => {
  return createSpan('process-order', async (span) => {
    span.setAttributes({
      'order.id': orderId,
      'operation': 'process'
    })
    
    // Business logic here
    const order = await getOrder(orderId)
    await validateOrder(order)
    await chargePayment(order)
    await updateInventory(order)
    
    return order
  })
}
```

Remember: Monitoring is about visibility, alerting is about action, and observability is about understanding. Implement comprehensive monitoring that covers infrastructure, applications, and business metrics. Use structured logging for better searchability, set up meaningful alerts that reduce noise, and leverage distributed tracing to understand complex system interactions.