package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;



import java.util.Date;

@Data
@Entity
public class Admin {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id_admin;
    private String username;
    private String password;
    private Date fecha_registro;
    private String correo;
}
