module.exports = {
  apps: [
    {
      name: 'capcut-creator',
      script: 'app.js',
      cwd: __dirname,
      instances: 1,
      exec_mode: 'fork',
      watch: false,
      autorestart: true,
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'production',
        PORT: process.env.PORT || 8000,
        MAX_GLOBAL_PER_DAY: process.env.MAX_GLOBAL_PER_DAY || 300,
        MAX_PER_IP_PER_DAY: process.env.MAX_PER_IP_PER_DAY || 25,
        LOCAL_ONLY: process.env.LOCAL_ONLY || 'true'
      },
      time: true,
      error_file: 'logs/pm2-error.log',
      out_file: 'logs/pm2-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss'
    }
  ]
};


