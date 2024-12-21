package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class HikariCpConfig {

    @Value("${DB_VENTADEAUTOS_URL}")
    private String dbVentadeautosUrl;
    @Value("${DB_VENTADEAUTOS_USER}")
    private String dbVentadeautosUser;
    @Value("${DB_VENTADEAUTOS_PASS}")
    private String dbVentadeautosPass;
    @Value("${DB_VENTADEAUTOS_DRIVER}")
    private String dbVentadeautosDriver;

    @Bean
    public HikariDataSource hikariDataSource() {

        HikariConfig config = new HikariConfig();

        /**
         * Configurar propiedad de conexion a BD
         */
        config.setJdbcUrl(dbVentadeautosUrl);
        config.setUsername(dbVentadeautosUser);
        config.setPassword(dbVentadeautosPass);
        config.setDriverClassName(dbVentadeautosDriver);

        /**
         * Configurar propiedades del pool de HikariCP
         * - MaximumPoolSize: Máximo # de conexiones del pool.
         * - MinimumIdle: Mínimo # de conexiones inactivas del pool.
         * - IdleTimeout: Tiempo máximo de espera para
         *      eliminar una conexión inactiva.
         * - ConnectionTimeout: Tiempo máximo de espera
         *      para conectarse a la BD.
         */
        config.setMaximumPoolSize(20);
        config.setMinimumIdle(5);
        config.setIdleTimeout(300000);
        config.setConnectionTimeout(30000);

        System.out.println("###### HikariCP initialized ######");
        return new HikariDataSource(config);

    }

}
