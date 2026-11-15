import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.TARGET_URL || 'http://host.docker.internal:3333';

export const options = {
  stages: [
    { duration: '10s', target: 200 }, // Rampa de subida hasta 200 usuarios concurrentes
    { duration: '20s', target: 200 }, // Carga sostenida con 200 usuarios concurrentes
    { duration: '5s', target: 0 },    // Rampa de descenso
  ],
  thresholds: {
    http_req_duration: ['p(95)<300'], // Criterio: 95% de peticiones bajo 300 ms
    http_req_failed: ['rate<0.01'],   // Criterio: tasa de error menor al 1%
  },
};

export default function () {
  const res = http.get(`${BASE_URL}/`);

  check(res, {
    'estado HTTP es 200': (r) => r.status === 200,
    'tiempo de respuesta < 300 ms': (r) => r.timings.duration < 300,
    'entrega interfaz Cuidarte+': (r) => r.body.includes('Cuidarte+'),
  });

  sleep(1);
}