// validate-domains.js
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const https = require('https');
const readline = require('readline');
require('dotenv').config();

const {
  VALIDATE_URL,
  AUTH_TOKEN,
  LOGIN_URL,
  LOGIN_USERNAME,
  LOGIN_PASSWORD,
  TENANT_ID = '00000000-0000-0000-0000-000000000000',
  NODE_TLS_REJECT_UNAUTHORIZED = '0'
} = process.env;

if (!VALIDATE_URL) {
  console.error('❌ Необходимо указать VALIDATE_URL в .env файле');
  process.exit(1);
}

// Если AUTH_TOKEN не задан, нужны данные для логина
if (!AUTH_TOKEN && (!LOGIN_URL || !LOGIN_USERNAME || !LOGIN_PASSWORD)) {
  console.error('❌ Необходимо указать AUTH_TOKEN или LOGIN_URL, LOGIN_USERNAME, LOGIN_PASSWORD в .env файле');
  process.exit(1);
}

let authToken = AUTH_TOKEN || null;

const agent = new https.Agent({
  rejectUnauthorized: NODE_TLS_REJECT_UNAUTHORIZED === '0' ? false : true
});

const CHECK_ROBJECT_QUERY = `mutation checkRobject($input: CheckRobjectInput!) {
  checkRobject(input: $input) {
    isValid
    diagnostics {
      message
      severity
      labels {
        message
        primary
        span {
          end
          start
          __typename
        }
        __typename
      }
      __typename
    }
    __typename
  }
}`;

const LOGIN_QUERY = `mutation login($input: LoginRequest!) {
  login(input: $input) {
    forceChangePasswordSession {
      passwordPolicySettings {
        minLength
        mustBeDigit
        mustBeComplex
        mustBeLowercase
        mustBeUppercase
        mustBeSpecialCharacter
        mustNotBeRepeatedAdjacent
        mustBeDifferentFromPrevious
        __typename
      }
      reason
      sessionId
      __typename
    }
    loginResult {
      accessToken
      refreshToken
      passwordExpiresInMs
      __typename
    }
    secondFactor {
      connected
      isEnabled
      sessionToken
      __typename
    }
    __typename
  }
}`;

const stats = {
  totalDomains: 0,
  valid: 0,
  invalid: 0,
  skippedNonDomain: 0,
  errors: 0
};

class Spinner {
  constructor(text) {
    this.text = text;
    this.frames = ['|', '/', '-', '\\'];
    this.currentFrame = 0;
    this.interval = null;
  }

  start() {
    this.interval = setInterval(() => {
      process.stdout.write(`\r${this.frames[this.currentFrame]} ${this.text}`);
      this.currentFrame = (this.currentFrame + 1) % this.frames.length;
    }, 100);
  }

  stop(clear = true) {
    clearInterval(this.interval);
    if (clear) {
      process.stdout.write('\r' + ' '.repeat(60) + '\r');
    }
  }
}

function walkDir(dir, callback) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      walkDir(fullPath, callback);
    } else if (file.endsWith('.ro')) {
      callback(fullPath);
    }
  }
}

function parseLenientYaml(content) {
  const lenientSchema = yaml.DEFAULT_SCHEMA.extend({
    implicit: [
      new yaml.Type('tag:yaml.org,2002:str', {
        kind: 'scalar',
        resolve: () => true,
        construct: (data) => data || ''
      })
    ]
  });

  const handleUnknownTag = (tag) => {
    return new yaml.Type(tag, {
      kind: 'scalar',
      resolve: () => true,
      construct: (data) => data
    });
  };

  const tagRegex = /![\w-]+/g;
  const tags = new Set();
  let match;
  while ((match = tagRegex.exec(content)) !== null) {
    tags.add(match[0]);
  }

  for (const tag of tags) {
    if (tag !== '!') {
      lenientSchema.explicit.push(handleUnknownTag(`tag:yaml.org,2002:${tag.slice(1)}`));
      lenientSchema.explicit.push(handleUnknownTag(tag));
    }
  }

  return yaml.load(content, { schema: lenientSchema });
}

function cleanYamlContent(content) {
  const lines = content.split('\n');
  const cleanedLines = [];
  for (let line of lines) {
    line = line.replace(/![\w-]+/g, '');
    line = line.replace(/[*&]/g, '');
    if (line.includes('!!binary') || line.includes('!!python')) {
      continue;
    }
    cleanedLines.push(line);
  }
  return cleanedLines.join('\n');
}

function parseYaml(content) {
  try {
    return yaml.load(content);
  } catch (e1) {
    try {
      return parseLenientYaml(content);
    } catch (e2) {
      const cleaned = cleanYamlContent(content);
      return yaml.load(cleaned);
    }
  }
}

// Функция авторизации
async function login() {
  if (authToken) {
    console.log('🔐 Используется AUTH_TOKEN из .env');
    return authToken;
  }

  console.log(`🔐 Выполняется вход под пользователем ${LOGIN_USERNAME}...`);

  const payload = {
    operationName: 'login',
    variables: {
      input: {
        password: LOGIN_PASSWORD,
        username: LOGIN_USERNAME
      }
    },
    query: LOGIN_QUERY
  };

  try {
    const response = await fetch(LOGIN_URL, {
      method: 'POST',
      headers: {
        'accept': '*/*',
        'content-type': 'application/json',
        'apollo-require-preflight': 'true'
      },
      body: JSON.stringify(payload),
      agent: LOGIN_URL.startsWith('https') ? agent : undefined
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    const loginData = result.data?.login;
    const accessToken = loginData?.loginResult?.accessToken;

    if (!accessToken) {
      throw new Error('В ответе логина отсутствует accessToken');
    }

    console.log('✅ Вход выполнен успешно');
    authToken = accessToken;
    return authToken;
  } catch (error) {
    console.error('❌ Ошибка входа:', error.message);
    process.exit(1);
  }
}

// Функция вывода полной диагностики
function printFullDiagnostics(domainId, filePath, diagnostics) {
  console.log(`\n❌ ${domainId || path.basename(filePath)}`);
  if (diagnostics && diagnostics.length > 0) {
    console.log('   Диагностика:');
    diagnostics.forEach((diag, idx) => {
      console.log(`   [${idx + 1}] Severity: ${diag.severity}`);
      console.log(`       Message: ${diag.message}`);
      if (diag.labels && diag.labels.length > 0) {
        diag.labels.forEach(label => {
          console.log(`       Label: ${label.message} (primary: ${label.primary})`);
          if (label.span) {
            console.log(`       Span: ${label.span.start} - ${label.span.end}`);
          }
        });
      }
    });
  } else {
    console.log('   Диагностика отсутствует.');
  }
}

async function validateDomain(filePath, briefMode, verboseMode, pendingDiagnostics) {
  const spinner = new Spinner(`Проверка: ${path.basename(filePath)}`);
  let domainId = null;

  try {
    const content = fs.readFileSync(filePath, 'utf8');
    let data;
    try {
      data = parseYaml(content);
    } catch (e) {
      stats.errors++;
      if (!briefMode) {
        console.error(`⚠️  Ошибка парсинга YAML в ${filePath}: ${e.message}`);
      } else {
        console.log(`⚠️ ${path.basename(filePath)}`);
      }
      return;
    }

    if (data.type !== 'domain') {
      stats.skippedNonDomain++;
      return;
    }

    stats.totalDomains++;
    domainId = data.id || path.basename(filePath, '.ro');
    
    spinner.start();

    const payload = {
      operationName: 'checkRobject',
      query: CHECK_ROBJECT_QUERY,
      variables: {
        input: {
          type: 'DOMAIN',
          sourceCode: content
        }
      }
    };

    const response = await fetch(VALIDATE_URL, {
      method: 'POST',
      headers: {
        'accept': '*/*',
        'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'apollo-require-preflight': 'true',
        'authorization': `Bearer ${authToken}`,
        'cache-control': 'no-cache',
        'content-type': 'application/json',
        'x-tenant-id': TENANT_ID,
        'Referer': VALIDATE_URL
      },
      body: JSON.stringify(payload),
      agent: VALIDATE_URL.startsWith('https') ? agent : undefined
    });

    if (response.status === 401) {
      throw new Error('HTTP 401 Unauthorized: токен истёк или недействителен');
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    const checkResult = result.data?.checkRobject;
    if (!checkResult) {
      throw new Error(`Некорректный ответ: ${JSON.stringify(result)}`);
    }

    spinner.stop();

    if (checkResult.isValid) {
      stats.valid++;
      if (briefMode) {
        console.log(`✅ ${domainId}`);
      } else {
        console.log(`✅ ${path.basename(filePath)}: OK`);
      }
    } else {
      stats.invalid++;
      if (briefMode) {
        console.log(`❌ ${domainId}`);
      } else if (verboseMode) {
        printFullDiagnostics(domainId, filePath, checkResult.diagnostics);
      } else {
        pendingDiagnostics.push({
          domainId,
          filePath,
          diagnostics: checkResult.diagnostics
        });
        console.log(`❌ ${path.basename(filePath)}: НЕВАЛИДЕН (диагностика будет доступна по запросу)`);
      }
    }
  } catch (error) {
    spinner.stop();
    stats.errors++;
    if (briefMode) {
      console.log(`⚠️ ${domainId || path.basename(filePath)}`);
    } else {
      console.error(`🚫 Ошибка при обработке ${filePath}: ${error.message}`);
    }
    // Прерываем выполнение при любых ошибках (включая 401)
    if (error.message.includes('401')) {
      console.error('❌ Выполнение прервано из-за ошибки авторизации');
      process.exit(1);
    }
  }
}

function askForDiagnostics(pendingDiagnostics) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  rl.question('Показать полную диагностику для невалидных доменов? (y/N): ', (answer) => {
    if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
      for (const item of pendingDiagnostics) {
        printFullDiagnostics(item.domainId, item.filePath, item.diagnostics);
      }
    }
    rl.close();
  });
}

async function main() {
  const args = process.argv.slice(2);
  const briefMode = args.includes('--brief');
  const verboseMode = args.includes('--verbose') || args.includes('-v');
  const helpMode = args.includes('--help') || args.includes('-h');
  const targetDir = args.find(arg => !arg.startsWith('--'));

  if (helpMode) {
    console.log('Использование: node validate-domains.js <каталог> [опции]');
    console.log('');
    console.log('Опции:');
    console.log('  --brief          Выводить только id всех проверенных доменов с отметкой ✅/❌/⚠️');
    console.log('  --verbose, -v    Показывать полную диагностику сразу для невалидных доменов');
    console.log('  --help, -h       Показать эту справку');
    console.log('');
    console.log('Режимы работы:');
    console.log('  По умолчанию     Краткий вывод: показывает только файл и статус (OK/НЕВАЛИДЕН).');
    console.log('                   После завершения запрашивает, показать ли полную диагностику');
    console.log('                   для невалидных доменов.');
    console.log('  --brief          Компактный список: для каждого проверенного домена выводится');
    console.log('                   ✅ id (валиден) или ❌ id (невалиден). Ошибки выполнения — ⚠️.');
    console.log('                   Диагностика не выводится.');
    console.log('  --verbose        Полная диагностика выводится сразу для каждого невалидного');
    console.log('                   домена, без дополнительных запросов.');
    console.log('');
    console.log('Примеры:');
    console.log('  node validate-domains.js ./domains');
    console.log('  node validate-domains.js ./domains --brief');
    console.log('  node validate-domains.js ./domains --verbose');
    process.exit(0);
  }

  if (!targetDir) {
    console.error('Использование: node validate-domains.js <каталог> [--brief] [--verbose] [--help]');
    process.exit(1);
  }

  if (!fs.existsSync(targetDir)) {
    console.error(`❌ Каталог не существует: ${targetDir}`);
    process.exit(1);
  }

  await login();

  console.log(`🔍 Начало валидации доменов в ${targetDir}`);
  console.log(`🌐 GraphQL URL: ${VALIDATE_URL}`);
  if (briefMode) console.log('📋 Режим brief: вывод id всех проверенных доменов с отметкой ✅/❌/⚠️\n');
  else if (verboseMode) console.log('📋 Режим verbose: полная диагностика сразу\n');
  else console.log('📋 Режим по умолчанию: краткий вывод + интерактивная диагностика\n');

  const domainFiles = [];
  walkDir(targetDir, (file) => domainFiles.push(file));

  console.log(`📄 Найдено .ro файлов: ${domainFiles.length}\n`);

  const pendingDiagnostics = [];

  for (const file of domainFiles) {
    await validateDomain(file, briefMode, verboseMode, pendingDiagnostics);
  }

  // Итоговая статистика
  console.log('\n' + '='.repeat(60));
  console.log('📊 ИТОГИ ВАЛИДАЦИИ');
  console.log('='.repeat(60));
  console.log(`Проверено доменов: ${stats.totalDomains}`);
  console.log(`Успешно (isValid=true): ${stats.valid}`);
  console.log(`С ошибками (isValid=false): ${stats.invalid}`);
  console.log(`Ошибки выполнения (⚠️): ${stats.errors}`);
  console.log(`Пропущено (не domain): ${stats.skippedNonDomain}`);

  // Запрос диагностики
  if (!briefMode && !verboseMode && pendingDiagnostics.length > 0) {
    console.log(''); // пустая строка
    await askForDiagnostics(pendingDiagnostics);
  }
}

main().catch(console.error);