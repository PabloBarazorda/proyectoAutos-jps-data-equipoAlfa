package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.entity;


import jakarta.persistence.*;
import lombok.*;

import java.util.Date;
import java.util.List;


@Entity
@Data
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor

public class Clientes {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer idUsuario;
    private String correo;
    private String username;
    private String nombre;
    private String apellidos;
    private String contrasenia;
    private Integer telefono;
    private String direccion;

    @Temporal(TemporalType.TIMESTAMP)
    private Date fechaRegistro;

    @PrePersist
    protected void onCreate() { fechaRegistro = new Date(); }

    @ToString.Exclude
    @OneToMany(mappedBy = "cliente")
    private List<CarritoCompras> carrito;

//
//    public Integer getIdUsuario() {
//        return idUsuario;
//    }
//
//    public void setIdUsuario(Integer idUsuario) {
//        this.idUsuario = idUsuario;
//    }
//
//    public String getCorreo() {
//        return correo;
//    }
//
//    public void setCorreo(String correo) {
//        this.correo = correo;
//    }
//
//    public String getUsername() {
//        return username;
//    }
//
//    public void setUsername(String username) {
//        this.username = username;
//    }
//
//    public String getNombre() {
//        return nombre;
//    }
//
//    public void setNombre(String nombre) {
//        this.nombre = nombre;
//    }
//
//    public String getApellidos() {
//        return apellidos;
//    }
//
//    public void setApellidos(String apellidos) {
//        this.apellidos = apellidos;
//    }
//
//    public String getContrasenia() {
//        return contrasenia;
//    }
//
//    public void setContrasenia(String contrasenia) {
//        this.contrasenia = contrasenia;
//    }
//
//    public Integer getTelefono() {
//        return telefono;
//    }
//
//    public void setTelefono(Integer telefono) {
//        this.telefono = telefono;
//    }
//
//    public String getDireccion() {
//        return direccion;
//    }
//
//    public void setDireccion(String direccion) {
//        this.direccion = direccion;
//    }
//
//    public Date getFechaRegistro() {
//        return fechaRegistro;
//    }
//
//    public void setFechaRegistro(Date fechaRegistro) {
//        this.fechaRegistro = fechaRegistro;
//    }
}
