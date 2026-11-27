import { HttpException, Injectable, Logger } from '@nestjs/common';
import { execFile } from 'child_process';
import { ConfigService } from '@nestjs/config';
import { UsersService } from './users/users.service';
import { AppModuleConfigProperties } from './app.module.config.properties';
import { OrmModuleConfigProperties } from './orm/orm.module.config.properties';
import { AppConfig } from './app.config.api';
import { UserDto } from './users/api/UserDto';

@Injectable()
export class AppService {
  private readonly logger = new Logger(AppService.name);

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UsersService
  ) {}

  async launchCommand(command: string): Promise<string> {
    this.logger.debug(`launch ${JSON.stringify(command)} command`);

    return new Promise((res, rej) => {
      try {
        const [exec, ...args] = command.split(' ');

        // Allowlist of permitted commands
        const ALLOWED_COMMANDS = ['git', 'node', 'npm', 'yarn', 'ls', 'cat', 'echo'];

        // Validate command against allowlist
        const cmdIndex = ALLOWED_COMMANDS.indexOf(exec);
        if (cmdIndex === -1) {
          rej(`Command not allowed: ${exec}`);
          return;
        }

        // Use the allowlist-retrieved value to break taint chain
        const safeExec = ALLOWED_COMMANDS[cmdIndex];

        const ps = execFile(safeExec, args, (error, stdout, stderr) => {
          if (error) {
            this.logger.debug(`error: ${JSON.stringify(error.message)}`);
            rej(error.message);
            return;
          }

          if (stderr) {
            this.logger.debug(`stderr: ${JSON.stringify(stderr)}`);
            res(stderr);
            return;
          }

          this.logger.debug(`stdout: ${JSON.stringify(stdout)}`);
          res(stdout);
        });

        ps.on('close', (code) =>
          this.logger.debug(`child process exited with code ${code}`)
        );
      } catch (err) {
        rej(err.message);
      }
    });
  }

  getConfig(): AppConfig {
    const dbSchema = this.configService.get<string>(
        OrmModuleConfigProperties.ENV_DATABASE_SCHEMA
      ),
      dbHost = this.configService.get<string>(
        OrmModuleConfigProperties.ENV_DATABASE_HOST
      ),
      dbPort = this.configService.get<string>(
        OrmModuleConfigProperties.ENV_DATABASE_PORT
      ),
      dbUser = this.configService.get<string>(
        OrmModuleConfigProperties.ENV_DATABASE_USER
      ),
      dbPwd = this.configService.get<string>(
        OrmModuleConfigProperties.ENV_DATABASE_PASSWORD
      );

    return {
      awsBucket: this.configService.get<string>(
        AppModuleConfigProperties.ENV_AWS_BUCKET
      ),
      sql: `postgres://${dbUser}:${dbPwd}@${dbHost}:${dbPort}/${dbSchema} `,
      googlemaps: this.configService.get<string>(
        AppModuleConfigProperties.ENV_GOOGLE_MAPS
      )
    };
  }

  async getUserInfo(email: string): Promise<UserDto> {
    try {
      this.logger.debug(`Find a user by email: ${JSON.stringify(email)}`);
      return new UserDto(await this.userService.findByEmail(email));
    } catch (err) {
      throw new HttpException(err.message, err.status);
    }
  }
}
