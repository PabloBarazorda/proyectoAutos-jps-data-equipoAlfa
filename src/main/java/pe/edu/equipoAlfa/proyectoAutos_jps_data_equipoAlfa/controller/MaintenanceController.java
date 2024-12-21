package pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
//import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.ClientesDetallesDto;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.dto.*;
import pe.edu.equipoAlfa.proyectoAutos_jps_data_equipoAlfa.service.MaintenanceService;

import java.util.List;

@Controller
@RequestMapping("/clientes")
public class MaintenanceController {
    @Autowired
    private MaintenanceService maintenanceService;


    @GetMapping("/login")
    public String login (Model model) {
        return "login";
    }

    @GetMapping("/restricted")
    public String restricted (Model model) {
        return "restricted";
    }


    @GetMapping("/listar")
    public String listarClientes(Model model) {
        List<ClientesListarDto> clients = maintenanceService.getAllClients();
        model.addAttribute("clients", clients);
        return "maintenance-listado";
    }

    @GetMapping("/detalle/{id}")
    public String getDetalleClientById(@PathVariable Integer id, Model model) {
        ClientesDetallesDto detalleclient = maintenanceService.getClienteDetalleById(id);
        model.addAttribute("client", detalleclient);
        return "maintenance-detalles";
    }

    @GetMapping("/registrar")
    public String mostrarFormularioRegistro(Model model) {
        model.addAttribute("cliente", new ClientesRegistrarDto(null, "", "", "", "", "", null, ""));
        return "maintenance-crear";
    }

    @PostMapping("/registrar")
    public String registrarCliente(@ModelAttribute("cliente") ClientesRegistrarDto clientesRegistrarDto) {
        maintenanceService.registrarCliente(clientesRegistrarDto);
        return "redirect:/clientes/listar";
    }

    @GetMapping("/editar/{id}")
    public String mostrarFormularioEditar(@PathVariable Integer id, Model model) {

        ClientesEditarDto clientesEditarDto = maintenanceService.getClientesEditarById(id);
        model.addAttribute("clientesEditarDto", clientesEditarDto);
        return "maintenance-editar";
    }

    @PostMapping("/editar/{id}")
    public String editarCliente(@PathVariable Integer id, @ModelAttribute ClientesEditarDto clientesEditarDto) {
        maintenanceService.postClientesEditarById(id, clientesEditarDto);
        return "redirect:/clientes/listar";
    }

//    @PostMapping("/delete/{id}")
//    public String deleteFilmById(@PathVariable int id, @ModelAttribute ClientesBorrarDto clientesBorrarDto) {
//        maintenanceService.postClientesBorrarById(id, clientesBorrarDto);
//        return "redirect:/clientes/listar";
//    }

    @PostMapping("/delete/{id}")
    public String deleteClienteById(@PathVariable int id) {
        try {
            maintenanceService.deleteClientesById(id);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return "redirect:/clientes/listar";
    }


}
